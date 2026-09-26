// Package store is the public-key directory persistence layer (ADR-023 §D5).
//
// It holds PUBLIC keys only. It never sees a private key, ratchet state, session
// key or plaintext — all of that lives on the client. The store does no crypto:
// it validates nothing about the key material beyond structural sanity handled at
// the API edge, and simply serves what was published.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound means the requested user (or user+device) has no published bundle.
var ErrNotFound = errors.New("key directory: not found")

// PreKey is a one-time prekey (public).
type PreKey struct {
	ID  int32
	Pub []byte
}

// SignedPreKey is a device's medium-term prekey plus its signature (public).
type SignedPreKey struct {
	ID  int32
	Pub []byte
	Sig []byte
}

// BundleUpload is what a device publishes for itself (KEY_PUBLISH).
type BundleUpload struct {
	DeviceID       string
	IdentityKey    []byte
	SignedPreKey   SignedPreKey
	OneTimePreKeys []PreKey
}

// DeviceBundle is what a peer fetches for a device (KEY_FETCH). OneTimePreKey is
// nil when the pool is exhausted — X3DH then falls back to SPK-only (ADR-023 §D5).
type DeviceBundle struct {
	DeviceID      string
	IdentityKey   []byte
	SignedPreKey  SignedPreKey
	OneTimePreKey *PreKey
	Remaining     int // un-consumed one-time prekeys left for this device
}

// Store is the directory contract. Implementations: Postgres (prod) and Memory (dev/e2e).
type Store interface {
	// Publish registers/updates a device's identity + signed prekey and appends one-time prekeys to its
	// pool. Bound to userID (the authenticated caller). Multi-device: publishing a device does NOT retire
	// the user's others — the client encrypts to all of them; stale ones age out via PruneStaleDevices.
	Publish(ctx context.Context, userID string, b BundleUpload) error

	// AddOneTimePreKeys appends to a device's pool (replenish) and returns the number of un-consumed
	// prekeys remaining. ErrNotFound if the device has no identity. Callers MUST use monotonic, never-
	// reused opk_ids: a reused id is dropped (the published public is kept) and logged, never overwritten.
	// Spent prekeys are purged and the un-consumed pool is capped, so per-device storage stays bounded.
	AddOneTimePreKeys(ctx context.Context, userID, deviceID string, opks []PreKey) (remaining int, err error)

	// FetchAndConsume returns the bundles for a peer, consuming one one-time prekey per device atomically.
	// deviceID == "" fetches ALL of the user's devices (the client encrypts to each). ErrNotFound if the
	// user (or named device) has no usable bundle. NOTE: not idempotent — a GET consumes a prekey.
	FetchAndConsume(ctx context.Context, userID, deviceID string) ([]DeviceBundle, error)

	// CountOneTimePreKeys reports the un-consumed pool size for a device (low-water check). An UNKNOWN
	// user+device is ErrNotFound (not 0) — the client's self-heal republish keys off that.
	CountOneTimePreKeys(ctx context.Context, userID, deviceID string) (int, error)

	// DeleteDevice revokes a device: removes its identity + signed/one-time prekeys. Scoped to userID so a
	// caller only ever deletes its own device. ErrNotFound if the device doesn't exist.
	DeleteDevice(ctx context.Context, userID, deviceID string) error

	// PruneStaleDevices removes devices not seen (published/touched) within `olderThan`, but NEVER a user's
	// most-recent device (keep-newest), so every user keeps at least one and stays reachable. This is the
	// dead-device GC: an abandoned device (e.g. after a reinstall) ages out, while live ones — refreshed by
	// the client's touch-on-start — stay. Returns the number removed. (FK cascade drops their prekeys.)
	PruneStaleDevices(ctx context.Context, olderThan time.Duration) (removed int, err error)

	// Ping checks backend liveness.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close()
}
