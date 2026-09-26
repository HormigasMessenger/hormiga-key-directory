package store

import (
	"context"
	"testing"
)

// Multi-device: a user may run several devices. KEY_FETCH must return ALL of them (the client encrypts to
// each so every device gets a decryptable copy), and publishing one device must NOT retire the others.
// (Regression guard: an earlier "serve only the latest" + "retire others on publish" dropped messages for
// a peer reading on a different device.)
func TestMemory_FetchAll_ServesAllDevices(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	if err := m.Publish(ctx, "u1", idBundle("dev-a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(ctx, "u1", idBundle("dev-b", 2)); err != nil { // second device
		t.Fatal(err)
	}

	bundles, err := m.FetchAndConsume(ctx, "u1", "")
	if err != nil {
		t.Fatalf("fetch all: %v", err)
	}
	if len(bundles) != 2 {
		t.Fatalf("want BOTH devices served, got %d", len(bundles))
	}
	got := map[string]bool{bundles[0].DeviceID: true, bundles[1].DeviceID: true}
	if !got["dev-a"] || !got["dev-b"] {
		t.Fatalf("want dev-a and dev-b, got %+v", got)
	}
	// Publishing dev-b did not retire dev-a: both resolve by specific-device fetch too.
	if _, err := m.FetchAndConsume(ctx, "u1", "dev-a"); err != nil {
		t.Fatalf("dev-a should still exist: %v", err)
	}
	if _, err := m.FetchAndConsume(ctx, "u1", "dev-b"); err != nil {
		t.Fatalf("dev-b should still exist: %v", err)
	}
}
