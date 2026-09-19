package store

import (
	"context"
	"testing"
)

func idBundle(dev string, opkIDs ...int32) BundleUpload {
	b := BundleUpload{
		DeviceID:     dev,
		IdentityKey:  []byte{0x01},
		SignedPreKey: SignedPreKey{ID: 1, Pub: []byte{0x02}, Sig: []byte{0x03}},
	}
	for _, id := range opkIDs {
		b.OneTimePreKeys = append(b.OneTimePreKeys, PreKey{ID: id, Pub: []byte{byte(id)}})
	}
	return b
}

// C2: an unknown user+device must be ErrNotFound (not 0) — the client's self-heal republish keys off that.
func TestMemory_CountUnknownDevice_IsNotFound(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.CountOneTimePreKeys(ctx, "u", "ghost"); err != ErrNotFound {
		t.Fatalf("unknown device: want ErrNotFound, got %v", err)
	}
	if err := m.Publish(ctx, "u", idBundle("d", 1, 2)); err != nil {
		t.Fatal(err)
	}
	n, err := m.CountOneTimePreKeys(ctx, "u", "d")
	if err != nil || n != 2 {
		t.Fatalf("known device: want (2,nil), got (%d,%v)", n, err)
	}
}

// H3: a reused opk_id is dropped, not double-counted (the published public wins).
func TestMemory_ReplenishReusedIdDropped(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.Publish(ctx, "u", idBundle("d", 1, 2)); err != nil {
		t.Fatal(err)
	}
	rem, err := m.AddOneTimePreKeys(ctx, "u", "d", []PreKey{{ID: 2, Pub: []byte{0x22}}, {ID: 3, Pub: []byte{0x33}}})
	if err != nil {
		t.Fatal(err)
	}
	if rem != 3 { // ids {1,2,3}; the reused 2 must not double
		t.Fatalf("want 3 unconsumed after reusing id 2, got %d", rem)
	}
}

// C5: an owner revokes a device — it's gone, and a fetch no longer resolves it.
func TestMemory_DeleteDevice(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.DeleteDevice(ctx, "u", "ghost"); err != ErrNotFound {
		t.Fatalf("unknown device: want ErrNotFound, got %v", err)
	}
	if err := m.Publish(ctx, "u", idBundle("d", 1)); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteDevice(ctx, "u", "d"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if _, err := m.FetchAndConsume(ctx, "u", ""); err != ErrNotFound {
		t.Fatalf("after revoke, fetch: want ErrNotFound, got %v", err)
	}
	if err := m.DeleteDevice(ctx, "u", "d"); err != ErrNotFound {
		t.Fatalf("double delete: want ErrNotFound, got %v", err)
	}
}

// Pool cap: the un-consumed pool never grows past the ceiling, however much a client sends.
func TestMemory_PoolCapped(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.Publish(ctx, "u", idBundle("d")); err != nil { // no OPKs initially
		t.Fatal(err)
	}
	full := make([]PreKey, maxUnconsumedOPK)
	for i := range full {
		full[i] = PreKey{ID: int32(i + 1), Pub: []byte{byte(i)}}
	}
	rem, err := m.AddOneTimePreKeys(ctx, "u", "d", full)
	if err != nil {
		t.Fatal(err)
	}
	if rem != maxUnconsumedOPK {
		t.Fatalf("want pool filled to cap %d, got %d", maxUnconsumedOPK, rem)
	}
	rem2, err := m.AddOneTimePreKeys(ctx, "u", "d", []PreKey{{ID: 99999, Pub: []byte{0x09}}})
	if err != nil {
		t.Fatal(err)
	}
	if rem2 != maxUnconsumedOPK {
		t.Fatalf("cap breached: want %d, got %d", maxUnconsumedOPK, rem2)
	}
}
