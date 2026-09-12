package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBlocksAndRefills(t *testing.T) {
	l := New(60) // eine Anfrage pro Sekunde, Eimer fasst 60
	now := time.Now()

	for i := 0; i < 60; i++ {
		if res := l.Allow("k1", now); !res.Allowed {
			t.Fatalf("Anfrage %d wurde bereits abgewiesen", i+1)
		}
	}
	res := l.Allow("k1", now)
	if res.Allowed {
		t.Error("61. Anfrage in derselben Sekunde wurde durchgelassen")
	}
	if res.RetryAfter <= 0 {
		t.Error("RetryAfter fehlt für eine abgewiesene Anfrage")
	}
	if res := l.Allow("k1", now.Add(2*time.Second)); !res.Allowed {
		t.Error("Eimer füllt sich nicht wieder auf")
	}
	// Keys do not interfere with each other.
	if res := l.Allow("k2", now); !res.Allowed {
		t.Error("ein anderer Key wurde vom ersten mitbegrenzt")
	}
}

func TestLimiterCleanup(t *testing.T) {
	l := New(10)
	now := time.Now()
	l.Allow("alt", now)
	l.Allow("neu", now.Add(time.Hour))
	l.Cleanup(now.Add(time.Hour), 30*time.Minute)
	if _, ok := l.buckets["alt"]; ok {
		t.Error("alter Eimer wurde nicht aufgeräumt")
	}
	if _, ok := l.buckets["neu"]; !ok {
		t.Error("frischer Eimer wurde entfernt")
	}
}
