package store

import (
	"context"
	"testing"
	"time"
)

// Stale-device GC: age out abandoned devices, but keep-newest per user (never leave a user with zero).
func TestMemory_PruneStaleDevices_KeepNewest(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	old := 40 * 24 * time.Hour
	ttl := 30 * 24 * time.Hour

	// User A: an abandoned old device + a live new one.
	if err := m.Publish(ctx, "A", idBundle("a-old")); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(ctx, "A", idBundle("a-new")); err != nil {
		t.Fatal(err)
	}
	m.devices["A"]["a-old"].updatedAt = time.Now().Add(-old) // stale
	// a-new keeps time.Now() (fresh)

	// User B: a single dormant device — stale, but the only one → must be KEPT (reachability).
	if err := m.Publish(ctx, "B", idBundle("b-solo")); err != nil {
		t.Fatal(err)
	}
	m.devices["B"]["b-solo"].updatedAt = time.Now().Add(-old)

	// User C: two live devices — neither stale → both kept (multi-device intact).
	if err := m.Publish(ctx, "C", idBundle("c-1")); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(ctx, "C", idBundle("c-2")); err != nil {
		t.Fatal(err)
	}

	removed, err := m.PruneStaleDevices(ctx, ttl)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("want exactly 1 pruned (A/a-old), got %d", removed)
	}
	if _, err := m.FetchAndConsume(ctx, "A", "a-old"); err != ErrNotFound {
		t.Fatalf("A/a-old should be pruned, got %v", err)
	}
	if _, err := m.FetchAndConsume(ctx, "A", "a-new"); err != nil {
		t.Fatalf("A/a-new (live) must remain: %v", err)
	}
	if _, err := m.FetchAndConsume(ctx, "B", "b-solo"); err != nil {
		t.Fatalf("B/b-solo (dormant single) must be kept — keep-newest: %v", err)
	}
	cDevs, err := m.FetchAndConsume(ctx, "C", "")
	if err != nil || len(cDevs) != 2 {
		t.Fatalf("C's two live devices must both remain, got %d (%v)", len(cDevs), err)
	}
}
