package store

import (
	"bytes"
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory directory for dev/e2e only (mirrors the messenger's
// StubClientDirectory). Not for production: state is lost on restart and it is
// single-process. Semantics match Postgres: lowest-id one-time prekey consumed
// first, nil when the pool is exhausted.
type Memory struct {
	mu      sync.Mutex
	devices map[string]map[string]*memDevice // userID -> deviceID -> device
}

type memDevice struct {
	identityKey []byte
	spk         SignedPreKey
	hasSPK      bool
	opks        map[int32][]byte // un-consumed only; consumed ones are removed
	updatedAt   time.Time        // last publish/touch (for the stale-device GC; keep-newest)
}

func NewMemory() *Memory {
	return &Memory{devices: map[string]map[string]*memDevice{}}
}

func (m *Memory) Ping(context.Context) error { return nil }
func (m *Memory) Close()                      {}

func (m *Memory) dev(userID, deviceID string, create bool) *memDevice {
	byDev := m.devices[userID]
	if byDev == nil {
		if !create {
			return nil
		}
		byDev = map[string]*memDevice{}
		m.devices[userID] = byDev
	}
	d := byDev[deviceID]
	if d == nil && create {
		d = &memDevice{opks: map[int32][]byte{}}
		byDev[deviceID] = d
	}
	return d
}

func (m *Memory) Publish(_ context.Context, userID string, b BundleUpload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.dev(userID, b.DeviceID, false); existing != nil && existing.hasSPK && !bytes.Equal(existing.identityKey, b.IdentityKey) {
		slog.Warn("device identity key changed on publish (peers' safety numbers will shift)",
			"user", userID, "device", b.DeviceID)
	}
	d := m.dev(userID, b.DeviceID, true)
	d.identityKey = append([]byte(nil), b.IdentityKey...)
	d.spk = SignedPreKey{ID: b.SignedPreKey.ID, Pub: append([]byte(nil), b.SignedPreKey.Pub...), Sig: append([]byte(nil), b.SignedPreKey.Sig...)}
	d.hasSPK = true
	d.updatedAt = time.Now() // last publish/touch — drives the stale-device GC
	for _, o := range b.OneTimePreKeys {
		if _, ok := d.opks[o.ID]; !ok {
			d.opks[o.ID] = append([]byte(nil), o.Pub...)
		}
	}
	// Multi-device: publishing a device does NOT retire the user's others — the client encrypts to all.
	return nil
}

func (m *Memory) AddOneTimePreKeys(_ context.Context, userID, deviceID string, opks []PreKey) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dev(userID, deviceID, false)
	if d == nil {
		return 0, ErrNotFound
	}
	if len(d.opks) >= maxUnconsumedOPK { // cap the pool (mirrors Postgres)
		slog.Warn("one-time-prekey pool at cap; skipping replenish",
			"user", userID, "device", deviceID, "cap", maxUnconsumedOPK)
		return len(d.opks), nil
	}
	inserted := 0
	for _, o := range opks {
		if _, ok := d.opks[o.ID]; !ok {
			d.opks[o.ID] = append([]byte(nil), o.Pub...)
			inserted++
		}
	}
	if inserted < len(opks) { // reused id → dropped public (see Postgres insertOPKs / C1)
		slog.Warn("one-time-prekey id reuse: some publics dropped",
			"user", userID, "device", deviceID, "requested", len(opks), "inserted", inserted)
	}
	return len(d.opks), nil
}

func (m *Memory) FetchAndConsume(_ context.Context, userID, deviceID string) ([]DeviceBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byDev := m.devices[userID]
	if byDev == nil {
		return nil, ErrNotFound
	}
	var deviceIDs []string
	if deviceID == "" {
		// Serve ALL of the user's devices (multi-device delivery) — the client encrypts to each.
		for id := range byDev {
			deviceIDs = append(deviceIDs, id)
		}
		sort.Strings(deviceIDs)
	} else {
		if _, ok := byDev[deviceID]; !ok {
			return nil, ErrNotFound
		}
		deviceIDs = []string{deviceID}
	}

	var out []DeviceBundle
	for _, id := range deviceIDs {
		d := byDev[id]
		if !d.hasSPK {
			continue // unusable bundle
		}
		bundle := DeviceBundle{
			DeviceID:     id,
			IdentityKey:  append([]byte(nil), d.identityKey...),
			SignedPreKey: SignedPreKey{ID: d.spk.ID, Pub: append([]byte(nil), d.spk.Pub...), Sig: append([]byte(nil), d.spk.Sig...)},
		}
		if lowest, ok := lowestKey(d.opks); ok {
			bundle.OneTimePreKey = &PreKey{ID: lowest, Pub: d.opks[lowest]}
			delete(d.opks, lowest) // consume
		}
		bundle.Remaining = len(d.opks)
		out = append(out, bundle)
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (m *Memory) CountOneTimePreKeys(_ context.Context, userID, deviceID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dev(userID, deviceID, false)
	if d == nil {
		return 0, ErrNotFound
	}
	return len(d.opks), nil
}

func (m *Memory) DeleteDevice(_ context.Context, userID, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byDev := m.devices[userID]
	if byDev == nil {
		return ErrNotFound
	}
	if _, ok := byDev[deviceID]; !ok {
		return ErrNotFound
	}
	delete(byDev, deviceID)
	return nil
}

func (m *Memory) PruneStaleDevices(_ context.Context, olderThan time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, byDev := range m.devices {
		var newest time.Time // keep-newest: never prune a user's most-recent device
		for _, d := range byDev {
			if d.updatedAt.After(newest) {
				newest = d.updatedAt
			}
		}
		for id, d := range byDev {
			if d.updatedAt.Before(cutoff) && d.updatedAt.Before(newest) {
				delete(byDev, id)
				removed++
			}
		}
	}
	return removed, nil
}

func lowestKey(pool map[int32][]byte) (int32, bool) {
	first := true
	var min int32
	for k := range pool {
		if first || k < min {
			min, first = k, false
		}
	}
	return min, !first
}
