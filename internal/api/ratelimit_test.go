package api

import (
	"testing"
	"time"
)

func TestRateLimiter_BurstThenBlockThenRefill(t *testing.T) {
	rl := newRateLimiter(60, 3) // 1 token/sec, burst 3
	if rl == nil {
		t.Fatal("expected an enabled limiter")
	}
	for i := 0; i < 3; i++ {
		if !rl.allow("caller") {
			t.Fatalf("burst token %d should pass", i)
		}
	}
	if rl.allow("caller") {
		t.Fatal("4th call in a burst of 3 must be rate-limited")
	}
	// A different caller has its own independent budget.
	if !rl.allow("other") {
		t.Fatal("a different caller must not be throttled by the first")
	}
	// Simulate ~2s of elapsed time → ~2 tokens refill.
	rl.mu.Lock()
	rl.buckets["caller"].last = time.Now().Add(-2 * time.Second)
	rl.mu.Unlock()
	if !rl.allow("caller") {
		t.Fatal("token should be available after refill")
	}
}

func TestRateLimiter_DisabledWhenNonPositive(t *testing.T) {
	if newRateLimiter(0, 10) != nil {
		t.Fatal("perMin<=0 must disable the limiter (nil)")
	}
}
