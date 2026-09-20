package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is mandated by the coturn use-auth-secret / TURN REST API contract
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/auth"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

// Handlers holds the directory dependencies.
type Handlers struct {
	Store       store.Store
	MaxOPK      int
	MaxKeyBytes int

	// Ephemeral TURN credentials (coturn use-auth-secret / TURN REST API). TurnSecret MUST equal coturn's
	// static-auth-secret; empty disables the endpoint. The HMAC is pooled — the mint path is stateless
	// (no DB, no locks) so it parallelizes freely under load.
	TurnSecret  []byte
	TurnURIs    []string
	TurnTTL     int
	turnMACPool sync.Pool
	turnMACOnce sync.Once
}

// Publish handles KEY_PUBLISH: register a device's identity + signed prekey and
// seed its one-time prekey pool, bound to the authenticated caller.
func (h *Handlers) Publish(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	var req PublishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.DeviceID == "" {
		writeErr(w, http.StatusBadRequest, "deviceId is required")
		return
	}
	ik, ok := h.decodeKey(w, "identityKey", req.IdentityKey)
	if !ok {
		return
	}
	spkPub, ok := h.decodeKey(w, "signedPreKey.publicKey", req.SignedPreKey.PublicKey)
	if !ok {
		return
	}
	spkSig, ok := h.decodeKey(w, "signedPreKey.signature", req.SignedPreKey.Signature)
	if !ok {
		return
	}
	opks, ok := h.decodeOPKs(w, req.OneTimePreKeys)
	if !ok {
		return
	}

	b := store.BundleUpload{
		DeviceID:       req.DeviceID,
		IdentityKey:    ik,
		SignedPreKey:   store.SignedPreKey{ID: req.SignedPreKey.ID, Pub: spkPub, Sig: spkSig},
		OneTimePreKeys: opks,
	}
	if err := h.Store.Publish(r.Context(), userID, b); err != nil {
		writeErr(w, http.StatusInternalServerError, "publish failed")
		return
	}
	remaining, err := h.Store.CountOneTimePreKeys(r.Context(), userID, req.DeviceID)
	if err != nil {
		remaining = len(opks)
	}
	writeJSON(w, http.StatusOK, PublishResponse{DeviceID: req.DeviceID, OneTimePreKeysRemaining: remaining})
}

// Replenish tops up the caller's own device pool.
func (h *Handlers) Replenish(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	var req ReplenishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.DeviceID == "" {
		writeErr(w, http.StatusBadRequest, "deviceId is required")
		return
	}
	opks, ok := h.decodeOPKs(w, req.OneTimePreKeys)
	if !ok {
		return
	}
	remaining, err := h.Store.AddOneTimePreKeys(r.Context(), userID, req.DeviceID, opks)
	if err != nil {
		h.writeStoreErr(w, err, "replenish failed")
		return
	}
	writeJSON(w, http.StatusOK, CountResponse{DeviceID: req.DeviceID, OneTimePreKeysRemaining: remaining})
}

// FetchUser handles KEY_FETCH for every device of a peer.
func (h *Handlers) FetchUser(w http.ResponseWriter, r *http.Request) {
	h.fetch(w, r, r.PathValue("userId"), "")
}

// FetchDevice handles KEY_FETCH for one device of a peer.
func (h *Handlers) FetchDevice(w http.ResponseWriter, r *http.Request) {
	h.fetch(w, r, r.PathValue("userId"), r.PathValue("deviceId"))
}

func (h *Handlers) fetch(w http.ResponseWriter, r *http.Request, peerID, deviceID string) {
	if peerID == "" {
		writeErr(w, http.StatusBadRequest, "userId is required")
		return
	}
	bundles, err := h.Store.FetchAndConsume(r.Context(), peerID, deviceID)
	if err != nil {
		h.writeStoreErr(w, err, "fetch failed")
		return
	}
	resp := FetchResponse{UserID: peerID, Devices: make([]DeviceBundleDTO, 0, len(bundles))}
	for _, b := range bundles {
		d := DeviceBundleDTO{
			DeviceID:    b.DeviceID,
			IdentityKey: enc(b.IdentityKey),
			SignedPreKey: SignedPreKeyDTO{
				ID:        b.SignedPreKey.ID,
				PublicKey: enc(b.SignedPreKey.Pub),
				Signature: enc(b.SignedPreKey.Sig),
			},
			OneTimePreKeysRemaining: b.Remaining,
		}
		if b.OneTimePreKey != nil {
			d.OneTimePreKey = &PreKeyDTO{ID: b.OneTimePreKey.ID, PublicKey: enc(b.OneTimePreKey.Pub)}
		}
		resp.Devices = append(resp.Devices, d)
	}
	writeJSON(w, http.StatusOK, resp)
}

// SelfCount reports the caller's own device pool size (low-water check).
func (h *Handlers) SelfCount(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	deviceID := r.URL.Query().Get("deviceId")
	if deviceID == "" {
		writeErr(w, http.StatusBadRequest, "deviceId query parameter is required")
		return
	}
	n, err := h.Store.CountOneTimePreKeys(r.Context(), userID, deviceID)
	if err != nil {
		h.writeStoreErr(w, err, "count failed")
		return
	}
	writeJSON(w, http.StatusOK, CountResponse{DeviceID: deviceID, OneTimePreKeysRemaining: n})
}

// DeleteSelfDevice revokes one of the CALLER'S OWN devices — removes its identity + signed/one-time
// prekeys. deviceId is a path param; userId is the authenticated caller, so a client can only delete its
// own device. Used to retire a lost/compromised device. 204 on success, 404 if the device is unknown.
func (h *Handlers) DeleteSelfDevice(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	deviceID := r.PathValue("deviceId")
	if deviceID == "" {
		writeErr(w, http.StatusBadRequest, "deviceId is required")
		return
	}
	if err := h.Store.DeleteDevice(r.Context(), userID, deviceID); err != nil {
		h.writeStoreErr(w, err, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TurnCredentials mints SHORT-LIVED TURN credentials for the caller (coturn use-auth-secret / TURN REST
// API): username = "<expiry>:<userId>", credential = base64(HMAC-SHA1(secret, username)). coturn recomputes
// the same HMAC from its static-auth-secret and enforces the embedded expiry — so no static password is ever
// baked into the client and a leaked credential is useless within minutes. Stateless (no DB, no locks) →
// scales with request concurrency; the HMAC is pooled. 503 when TURN isn't configured (feature off).
func (h *Handlers) TurnCredentials(w http.ResponseWriter, r *http.Request) {
	if len(h.TurnSecret) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "turn credentials not configured")
		return
	}
	userID := auth.UserID(r.Context())
	expiry := time.Now().Unix() + int64(h.TurnTTL)
	username := strconv.FormatInt(expiry, 10) + ":" + userID

	h.turnMACOnce.Do(func() {
		h.turnMACPool.New = func() any { return hmac.New(sha1.New, h.TurnSecret) }
	})
	mac := h.turnMACPool.Get().(hash.Hash)
	mac.Reset()
	_, _ = mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	h.turnMACPool.Put(mac)

	writeJSON(w, http.StatusOK, TurnCredentialsResponse{
		Username:   username,
		Credential: credential,
		TTL:        h.TurnTTL,
		URIs:       h.TurnURIs,
	})
}

// ---- helpers ----

func (h *Handlers) decodeKey(w http.ResponseWriter, field, b64 string) ([]byte, bool) {
	if b64 == "" {
		writeErr(w, http.StatusBadRequest, field+" is required")
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, field+" must be base64")
		return nil, false
	}
	if len(raw) == 0 || len(raw) > h.MaxKeyBytes {
		writeErr(w, http.StatusBadRequest, field+" has an invalid length")
		return nil, false
	}
	return raw, true
}

func (h *Handlers) decodeOPKs(w http.ResponseWriter, in []PreKeyDTO) ([]store.PreKey, bool) {
	if len(in) > h.MaxOPK {
		writeErr(w, http.StatusBadRequest, "too many one-time prekeys in one request")
		return nil, false
	}
	out := make([]store.PreKey, 0, len(in))
	for _, o := range in {
		pub, ok := h.decodeKey(w, "oneTimePreKeys[].publicKey", o.PublicKey)
		if !ok {
			return nil, false
		}
		out = append(out, store.PreKey{ID: o.ID, Pub: pub})
	}
	return out, true
}

func (h *Handlers) writeStoreErr(w http.ResponseWriter, err error, genericMsg string) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no bundle for that identity")
		return
	}
	writeErr(w, http.StatusInternalServerError, genericMsg)
}

func enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Ping is exposed for readiness checks.
func ping(ctx context.Context, s store.Store) error { return s.Ping(ctx) }
