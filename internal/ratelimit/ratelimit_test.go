package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBlocksAndRefills(t *testing.T) {
	l := New(60) // one request per second, bucket holds 60
	now := time.Now()

	for i := 0; i < 60; i++ {
		if res := l.Allow("k1", now); !res.Allowed {
			t.Fatalf("request %d was already refused", i+1)
		}
	}
	res := l.Allow("k1", now)
	if res.Allowed {
		t.Error("the 61st request in the same second was let through")
	}
	if res.RetryAfter <= 0 {
		t.Error("RetryAfter missing on a refused request")
	}
	if res := l.Allow("k1", now.Add(2*time.Second)); !res.Allowed {
		t.Error("the bucket does not refill")
	}
	// Keys do not interfere with each other.
	if res := l.Allow("k2", now); !res.Allowed {
		t.Error("another key was throttled by the first")
	}
}

func TestLimiterCleanup(t *testing.T) {
	l := New(10)
	now := time.Now()
	l.Allow("alt", now)
	l.Allow("neu", now.Add(time.Hour))
	l.Cleanup(now.Add(time.Hour), 30*time.Minute)
	if _, ok := l.buckets["alt"]; ok {
		t.Error("the stale bucket was not cleaned up")
	}
	if _, ok := l.buckets["neu"]; !ok {
		t.Error("a fresh bucket was removed")
	}
}
