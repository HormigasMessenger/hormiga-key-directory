package store_test

import (
	"context"
	"os"
	"testing"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/migrate"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

// Real-Postgres integration test. Skipped unless KD_TEST_DATABASE_URL is set.
//
//	KD_TEST_DATABASE_URL='postgres://hormiga:hormiga@localhost:5433/hormiga_keys' go test ./internal/store/ -run Integration -v
func TestIntegration_PublishFetchConsume(t *testing.T) {
	dsn := os.Getenv("KD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("KD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pg, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pg.Close()
	if err := migrate.Run(ctx, pg.Pool()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Clean slate for this user (idempotent test run).
	if _, err := pg.Pool().Exec(ctx, `DELETE FROM e2e_identity WHERE user_id = 'it-alice'`); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	b := store.BundleUpload{
		DeviceID:     "dev-a",
		IdentityKey:  []byte("ik-pub"),
		SignedPreKey: store.SignedPreKey{ID: 1, Pub: []byte("spk-pub"), Sig: []byte("spk-sig")},
		OneTimePreKeys: []store.PreKey{
			{ID: 30, Pub: []byte("o30")},
			{ID: 10, Pub: []byte("o10")},
			{ID: 20, Pub: []byte("o20")},
		},
	}
	if err := pg.Publish(ctx, "it-alice", b); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Publish is idempotent (re-publish must not error or duplicate OPKs).
	if err := pg.Publish(ctx, "it-alice", b); err != nil {
		t.Fatalf("re-publish: %v", err)
	}
	if n, _ := pg.CountOneTimePreKeys(ctx, "it-alice", "dev-a"); n != 3 {
		t.Fatalf("want 3 OPKs after idempotent re-publish, got %d", n)
	}

	// Fetch consumes lowest-id first: 10, 20, 30, then nil (SPK-only).
	wantIDs := []int32{10, 20, 30}
	for i, want := range wantIDs {
		bundles, err := pg.FetchAndConsume(ctx, "it-alice", "dev-a")
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if len(bundles) != 1 || bundles[0].OneTimePreKey == nil {
			t.Fatalf("fetch %d: expected an OPK, got %+v", i, bundles)
		}
		if bundles[0].OneTimePreKey.ID != want {
			t.Fatalf("fetch %d: want OPK %d, got %d", i, want, bundles[0].OneTimePreKey.ID)
		}
		if bundles[0].Remaining != len(wantIDs)-1-i {
			t.Fatalf("fetch %d: want remaining %d, got %d", i, len(wantIDs)-1-i, bundles[0].Remaining)
		}
	}
	exhausted, err := pg.FetchAndConsume(ctx, "it-alice", "dev-a")
	if err != nil {
		t.Fatalf("fetch exhausted: %v", err)
	}
	if exhausted[0].OneTimePreKey != nil {
		t.Fatalf("want nil OPK after exhaustion, got %+v", exhausted[0].OneTimePreKey)
	}
	if exhausted[0].SignedPreKey.ID != 1 {
		t.Fatal("SPK must still be served on the SPK-only fallback")
	}

	// Replenish tops the pool back up.
	remaining, err := pg.AddOneTimePreKeys(ctx, "it-alice", "dev-a", []store.PreKey{{ID: 40, Pub: []byte("o40")}})
	if err != nil {
		t.Fatalf("replenish: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("want 1 remaining after replenish, got %d", remaining)
	}

	// Unknown identity → ErrNotFound.
	if _, err := pg.FetchAndConsume(ctx, "it-nobody", ""); err != store.ErrNotFound {
		t.Fatalf("want ErrNotFound for unknown user, got %v", err)
	}
	if _, err := pg.AddOneTimePreKeys(ctx, "it-alice", "ghost", []store.PreKey{{ID: 1, Pub: []byte("x")}}); err != store.ErrNotFound {
		t.Fatalf("want ErrNotFound for unknown device, got %v", err)
	}
}
