package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"log/slog"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

func testRouter() http.Handler {
	s := store.NewMemory()
	h := &Handlers{Store: s, MaxOPK: 200, MaxKeyBytes: 1024}
	return Router(s, h, "X-User-Id", slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))) //nolint
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func publish(t *testing.T, r http.Handler, user, device string, opkIDs ...int32) {
	t.Helper()
	opks := make([]PreKeyDTO, 0, len(opkIDs))
	for _, id := range opkIDs {
		opks = append(opks, PreKeyDTO{ID: id, PublicKey: b64("opk-pub")})
	}
	body, _ := json.Marshal(PublishRequest{
		DeviceID:       device,
		IdentityKey:    b64("ik-pub"),
		SignedPreKey:   SignedPreKeyDTO{ID: 1, PublicKey: b64("spk-pub"), Signature: b64("spk-sig")},
		OneTimePreKeys: opks,
	})
	req := httptest.NewRequest("POST", "/v1/keys", bytes.NewReader(body))
	req.Header.Set("X-User-Id", user)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("publish %s/%s: got %d, body %s", user, device, w.Code, w.Body.String())
	}
}

func TestPublishRequiresAuth(t *testing.T) {
	r := testRouter()
	body, _ := json.Marshal(PublishRequest{DeviceID: "d1", IdentityKey: b64("ik")})
	req := httptest.NewRequest("POST", "/v1/keys", bytes.NewReader(body))
	// no X-User-Id header
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestFetchConsumesLowestOPKInOrder(t *testing.T) {
	r := testRouter()
	publish(t, r, "alice", "dev-a", 30, 10, 20) // pool {10,20,30}

	got := fetchDevice(t, r, "bob", "alice", "dev-a")
	if len(got.Devices) != 1 {
		t.Fatalf("want 1 device, got %d", len(got.Devices))
	}
	d := got.Devices[0]
	if d.OneTimePreKey == nil || d.OneTimePreKey.ID != 10 {
		t.Fatalf("want lowest opk 10 consumed first, got %+v", d.OneTimePreKey)
	}
	if d.OneTimePreKeysRemaining != 2 {
		t.Fatalf("want 2 remaining, got %d", d.OneTimePreKeysRemaining)
	}

	// Next fetch consumes 20, then 30, then exhausts to nil (SPK-only fallback).
	if id := fetchDevice(t, r, "bob", "alice", "dev-a").Devices[0].OneTimePreKey.ID; id != 20 {
		t.Fatalf("want 20 next, got %d", id)
	}
	if id := fetchDevice(t, r, "bob", "alice", "dev-a").Devices[0].OneTimePreKey.ID; id != 30 {
		t.Fatalf("want 30 next, got %d", id)
	}
	last := fetchDevice(t, r, "bob", "alice", "dev-a").Devices[0]
	if last.OneTimePreKey != nil {
		t.Fatalf("want nil opk after exhaustion, got %+v", last.OneTimePreKey)
	}
	if last.OneTimePreKeysRemaining != 0 {
		t.Fatalf("want 0 remaining, got %d", last.OneTimePreKeysRemaining)
	}
	// SPK is still served on the SPK-only fallback.
	if last.SignedPreKey.PublicKey == "" {
		t.Fatal("SPK must still be served when the pool is exhausted")
	}
}

func TestFetchUnknownUser404(t *testing.T) {
	r := testRouter()
	req := httptest.NewRequest("GET", "/v1/keys/nobody", nil)
	req.Header.Set("X-User-Id", "bob")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestPublishBoundToCallerNotBody(t *testing.T) {
	r := testRouter()
	// alice publishes; the row must be keyed by the header identity, not anything in the body.
	publish(t, r, "alice", "dev-a", 1)
	// bob fetching alice sees alice's bundle.
	got := fetchDevice(t, r, "bob", "alice", "dev-a")
	if got.UserID != "alice" || len(got.Devices) != 1 {
		t.Fatalf("expected alice's bundle, got %+v", got)
	}
}

func TestReplenishUnknownDevice404(t *testing.T) {
	r := testRouter()
	body, _ := json.Marshal(ReplenishRequest{DeviceID: "ghost", OneTimePreKeys: []PreKeyDTO{{ID: 9, PublicKey: b64("p")}}})
	req := httptest.NewRequest("POST", "/v1/keys/one-time", bytes.NewReader(body))
	req.Header.Set("X-User-Id", "alice")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown device, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRejectsBadBase64(t *testing.T) {
	r := testRouter()
	body, _ := json.Marshal(PublishRequest{
		DeviceID:     "d1",
		IdentityKey:  "!!!not-base64!!!",
		SignedPreKey: SignedPreKeyDTO{ID: 1, PublicKey: b64("s"), Signature: b64("g")},
	})
	req := httptest.NewRequest("POST", "/v1/keys", bytes.NewReader(body))
	req.Header.Set("X-User-Id", "alice")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad base64, got %d", w.Code)
	}
}

func fetchDevice(t *testing.T, r http.Handler, caller, peer, device string) FetchResponse {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/keys/"+peer+"/"+device, nil)
	req.Header.Set("X-User-Id", caller)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fetch %s/%s: got %d, body %s", peer, device, w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}
