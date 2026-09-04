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
	// Publish registers/updates a device's identity + signed prekey and appends
	// one-time prekeys to its pool. Bound to userID (the authenticated caller).
	Publish(ctx context.Context, userID string, b BundleUpload) error

	// AddOneTimePreKeys appends to a device's pool (replenish) and returns the
	// number of un-consumed prekeys remaining. ErrNotFound if the device has no identity.
	AddOneTimePreKeys(ctx context.Context, userID, deviceID string, opks []PreKey) (remaining int, err error)

	// FetchAndConsume returns the bundles for a peer, consuming one one-time prekey
	// per device atomically. deviceID == "" fetches every device of the user.
	// ErrNotFound if the user (or the named device) has no usable bundle.
	FetchAndConsume(ctx context.Context, userID, deviceID string) ([]DeviceBundle, error)

	// CountOneTimePreKeys reports the un-consumed pool size for a device (low-water check).
	CountOneTimePreKeys(ctx context.Context, userID, deviceID string) (int, error)

	// Ping checks backend liveness.
	Ping(ctx context.Context) error

	// Close releases resources.
	Close()
}
