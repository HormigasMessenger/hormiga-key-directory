package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/auth"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

// Router wires the directory endpoints. Health checks are unauthenticated; every
// /v1 route sits behind the Oathkeeper-injected identity header.
func Router(s store.Store, h *Handlers, userHeader string, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := ping(r.Context(), s); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "not ready")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	authed := auth.Middleware(userHeader)

	// KEY_PUBLISH and pool management (caller's own identity).
	mux.Handle("POST /v1/keys", authed(http.HandlerFunc(h.Publish)))
	mux.Handle("POST /v1/keys/one-time", authed(http.HandlerFunc(h.Replenish)))
	mux.Handle("GET /v1/keys/self/count", authed(http.HandlerFunc(h.SelfCount)))

	// KEY_FETCH (a peer's public bundle; consumes one one-time prekey per device).
	mux.Handle("GET /v1/keys/{userId}", authed(http.HandlerFunc(h.FetchUser)))
	mux.Handle("GET /v1/keys/{userId}/{deviceId}", authed(http.HandlerFunc(h.FetchDevice)))

	return logging(log, mux)
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}
