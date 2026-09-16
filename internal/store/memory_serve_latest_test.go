package store

import (
	"context"
	"testing"
)

// v1 single-device: when a user re-provisions (new device_id, e.g. cleared storage / new browser),
// the directory must hand a peer ONLY the current (latest-published) device — never the dead ones it
// left behind. Otherwise a peer can't tell which identity is live and the safety number, hashed per
// identity key, is computed against a stale device and never matches. This locks that in for Memory
// (Postgres mirrors it via `ORDER BY updated_at DESC LIMIT 1`).
func TestMemory_FetchAll_ServesOnlyLatestDevice(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	up := func(dev string, ik byte) BundleUpload {
		return BundleUpload{
			DeviceID:       dev,
			IdentityKey:    []byte{ik},
			SignedPreKey:   SignedPreKey{ID: 1, Pub: []byte{ik, 1}, Sig: []byte{ik, 2}},
			OneTimePreKeys: []PreKey{{ID: 1, Pub: []byte{ik, 3}}},
		}
	}

	// Three successive provisions of the SAME user, newest last.
	if err := m.Publish(ctx, "u1", up("old-a", 0xA1)); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(ctx, "u1", up("old-b", 0xB2)); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(ctx, "u1", up("current", 0xC3)); err != nil {
		t.Fatal(err)
	}

	bundles, err := m.FetchAndConsume(ctx, "u1", "")
	if err != nil {
		t.Fatalf("fetch all: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("want exactly 1 (latest) device, got %d", len(bundles))
	}
	if bundles[0].DeviceID != "current" {
		t.Fatalf("want the latest device %q, got %q", "current", bundles[0].DeviceID)
	}
	if len(bundles[0].IdentityKey) != 1 || bundles[0].IdentityKey[0] != 0xC3 {
		t.Fatalf("want the current identity key, got %v", bundles[0].IdentityKey)
	}

	// Re-publishing an OLDER device makes it current again (highest seq wins).
	if err := m.Publish(ctx, "u1", up("old-a", 0xA1)); err != nil {
		t.Fatal(err)
	}
	bundles, err = m.FetchAndConsume(ctx, "u1", "")
	if err != nil {
		t.Fatalf("fetch all after re-publish: %v", err)
	}
	if len(bundles) != 1 || bundles[0].DeviceID != "old-a" {
		t.Fatalf("want re-published device to become current, got %+v", bundles)
	}

	// A specific-device fetch still reaches any device by id (unchanged behavior).
	if _, err := m.FetchAndConsume(ctx, "u1", "old-b"); err != nil {
		t.Fatalf("specific-device fetch should still work: %v", err)
	}
}
