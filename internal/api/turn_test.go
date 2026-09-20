package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // matches coturn's TURN REST API HMAC-SHA1
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

func turnRouter(secret string) http.Handler {
	s := store.NewMemory()
	h := &Handlers{
		Store: s, MaxOPK: 200, MaxKeyBytes: 1024,
		TurnSecret: []byte(secret), TurnURIs: []string{"turn:host:3478?transport=udp"}, TurnTTL: 600,
	}
	return Router(s, h, "X-User-Id", slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)), 0, 0)
}

func TestTurnCredentials_MintsValidEphemeralCred(t *testing.T) {
	r := turnRouter("s3cr3t")
	req := httptest.NewRequest("GET", "/v1/turn/credentials", nil)
	req.Header.Set("X-User-Id", "alice")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp TurnCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// username = "<expiry>:<userId>", expiry ~ now + ttl, userId from the injected header.
	parts := strings.SplitN(resp.Username, ":", 2)
	if len(parts) != 2 || parts[1] != "alice" {
		t.Fatalf("username %q not <expiry>:alice", resp.Username)
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		t.Fatalf("expiry not an int: %v", err)
	}
	now := time.Now().Unix()
	if exp < now+590 || exp > now+610 {
		t.Fatalf("expiry %d not ~now+600 (now=%d)", exp, now)
	}
	// credential must be exactly what coturn will recompute from the shared secret.
	m := hmac.New(sha1.New, []byte("s3cr3t"))
	_, _ = m.Write([]byte(resp.Username))
	want := base64.StdEncoding.EncodeToString(m.Sum(nil))
	if resp.Credential != want {
		t.Fatalf("credential mismatch: got %q want %q", resp.Credential, want)
	}
	if resp.TTL != 600 || len(resp.URIs) != 1 || resp.URIs[0] != "turn:host:3478?transport=udp" {
		t.Fatalf("ttl/uris off: ttl=%d uris=%v", resp.TTL, resp.URIs)
	}
}

func TestTurnCredentials_DisabledWithoutSecret(t *testing.T) {
	r := turnRouter("") // feature off
	req := httptest.NewRequest("GET", "/v1/turn/credentials", nil)
	req.Header.Set("X-User-Id", "alice")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when unconfigured, got %d", w.Code)
	}
}

func TestTurnCredentials_RequiresAuth(t *testing.T) {
	r := turnRouter("s3cr3t")
	req := httptest.NewRequest("GET", "/v1/turn/credentials", nil) // no X-User-Id
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 unauthenticated, got %d", w.Code)
	}
}
