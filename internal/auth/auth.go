// Package auth trusts the Oathkeeper-injected identity header (ADR-006).
//
// The proxy strips any client-supplied trust header and re-injects it from the
// authenticated Kratos session. This service MUST therefore be network-isolated
// so the header is only ever set by the proxy — a directly reachable instance
// makes X-User-Id forgeable (ADR-006 residual risk).
package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey int

const userIDKey ctxKey = 0

// Middleware requires the injected user-id header and stashes it in the context.
func Middleware(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid := strings.TrimSpace(r.Header.Get(header))
			if uid == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey, uid)))
		})
	}
}

// UserID returns the authenticated caller id, or "" if unauthenticated.
func UserID(ctx context.Context) string {
	uid, _ := ctx.Value(userIDKey).(string)
	return uid
}
