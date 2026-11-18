package iplimiter

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type client struct {
	limiter      *rate.Limiter
	expiresAt    time.Time
	blockedUntil time.Time
}

type IpLimiter struct {
	ctx    context.Context
	ips    map[string]*client
	ttl    time.Duration
	r      rate.Limit
	b      int
	punish time.Duration

	m sync.Mutex
}

// Create new limiter by ip
// r, b - integer for "golang.org/x/time/rate"
// ttl - time to loop for ticker to clear
// punish - duration of punish, when iplimiter.Allow() return false
func NewLimiter(ctx context.Context, r rate.Limit, b int, ttl, punish time.Duration) *IpLimiter {
	if ttl <= 0 {
		panic("ttl must be above 0")
	}
	if punish <= 0 {
		panic("punish must be above 0")
	}
	if punish <= 0 {
		panic("burst must be above 0")
	}
	x := &IpLimiter{
		ctx:    ctx,
		ips:    make(map[string]*client, 50),
		r:      r,
		b:      b,
		ttl:    ttl,
		punish: punish,
	}
	go x.ipTicker()
	return x
}

// Allow ip, true if allowed, false if banned
// Works like "golang.org/x/time/rate", but for ip
func (x *IpLimiter) Allow(ip string) bool {
	now := time.Now()

	x.m.Lock()
	defer x.m.Unlock()

	cl := x.ips[ip]
	if cl == nil {
		cl = &client{
			limiter: rate.NewLimiter(x.r, x.b),
		}
	}
	if now.Before(cl.blockedUntil) {
		return false
	}

	cl.expiresAt = now.Add(x.ttl)
	x.ips[ip] = cl
	if !cl.limiter.Allow() {
		cl.blockedUntil = now.Add(x.punish)
		return false
	}

	return true
}

func (x *IpLimiter) ipTicker() {
	ticker := time.NewTicker(x.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-x.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			x.m.Lock()
			for ip, cl := range x.ips {
				if cl.expiresAt.Before(now) && cl.blockedUntil.Before(now) {
					delete(x.ips, ip)
				}
			}
			x.m.Unlock()
		}
	}
}
