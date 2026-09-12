// Package ratelimit caps requests per API key.
//
// State lives in process memory: an instance is one process over one SQLite
// file and cannot scale horizontally anyway, so a counter in the database
// would only add writes.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastFill time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	perMin  float64
	burst   float64
}

// New builds a limiter of perMin requests per minute. The bucket holds one
// minute's worth so a script may catch up briefly without sustained overuse.
func New(perMin int) *Limiter {
	if perMin < 1 {
		perMin = 1
	}
	return &Limiter{
		buckets: map[string]*bucket{},
		perMin:  float64(perMin),
		burst:   float64(perMin),
	}
}

type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	Reset      time.Time
	RetryAfter time.Duration
}

// Allow accounts for one request and returns the RateLimit header values, so
// callers can pace themselves instead of running into 429s.
func (l *Limiter) Allow(key string, now time.Time) Result {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.perMin/60)
		b.lastFill = now
	}

	res := Result{Limit: int(l.perMin)}
	if b.tokens < 1 {
		missing := 1 - b.tokens
		res.RetryAfter = time.Duration(missing / (l.perMin / 60) * float64(time.Second))
		res.Reset = now.Add(res.RetryAfter)
		return res
	}
	b.tokens--
	res.Allowed = true
	res.Remaining = int(b.tokens)
	res.Reset = now.Add(time.Duration((l.burst - b.tokens) / (l.perMin / 60) * float64(time.Second)))
	return res
}

// Cleanup drops buckets that have been idle.
func (l *Limiter) Cleanup(now time.Time, idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if now.Sub(b.lastFill) > idle {
			delete(l.buckets, key)
		}
	}
}
