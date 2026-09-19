package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/auth"
)

// Per-caller token-bucket rate limiter for KEY_FETCH. A fetch CONSUMES a peer's one-time prekey, so an
// authenticated caller could loop fetches to drain a victim's pool and force every new session to the
// weaker SPK-only path. We throttle by the authenticated caller id (X-User-Id, injected by Oathkeeper) —
// Oathkeeper itself has no rate-limit handler, and this is the only layer that sees the authenticated
// caller AND the target, while keeping the service crypto-free. In-memory (the service is single-instance).
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const rlIdleTTL = 15 * time.Minute // drop buckets unused this long (bounds memory)

// newRateLimiter returns a limiter, or nil (disabled) when perMin <= 0.
func newRateLimiter(perMin, burst int) *rateLimiter {
	if perMin <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = perMin
	}
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMin) / 60.0,
		burst:   float64(burst),
		lastGC:  time.Now(),
	}
}

// allow consumes one token for key, refilling by elapsed time. false → over budget.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now

	rl.gcLocked(now)

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gcLocked evicts idle buckets occasionally so the map can't grow without bound.
func (rl *rateLimiter) gcLocked(now time.Time) {
	if now.Sub(rl.lastGC) < rlIdleTTL {
		return
	}
	for k, b := range rl.buckets {
		if now.Sub(b.last) > rlIdleTTL {
			delete(rl.buckets, k)
		}
	}
	rl.lastGC = now
}

// rateLimit wraps a handler, throttling per authenticated caller. Must sit INSIDE the auth middleware so
// the caller id is in the context. A nil limiter is a pass-through (disabled).
func rateLimit(rl *rateLimiter, next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := auth.UserID(r.Context())
		if caller != "" && !rl.allow(caller) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
