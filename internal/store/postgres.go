package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxUnconsumedOPK caps the un-consumed one-time-prekey pool per device. A well-behaved client tops up to
// ~20; this bounds a buggy/abusive one and, with the consumed-row purge on replenish, keeps per-device
// storage bounded regardless of how many sessions the device has started.
const maxUnconsumedOPK = 200

// Postgres is the production directory store.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a pool against the given DSN.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

// Pool exposes the underlying pool (used by the migrator).
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) Publish(ctx context.Context, userID string, b BundleUpload) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Audit: an existing device re-publishing a DIFFERENT identity key silently shifts peers' safety
	// numbers (§D7). Normal clients never rotate identity (self-heal republishes the same key), so this
	// is a notable event worth a trail. Best-effort — a read error here must not block the publish.
	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT identity_key_pub FROM e2e_identity WHERE user_id = $1 AND device_id = $2`,
		userID, b.DeviceID).Scan(&prev); err == nil && !bytes.Equal(prev, b.IdentityKey) {
		slog.Warn("device identity key changed on publish (peers' safety numbers will shift)",
			"user", userID, "device", b.DeviceID)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO e2e_identity (user_id, device_id, identity_key_pub)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, device_id)
		 DO UPDATE SET identity_key_pub = EXCLUDED.identity_key_pub, updated_at = now()`,
		userID, b.DeviceID, b.IdentityKey); err != nil {
		return fmt.Errorf("upsert identity: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO e2e_signed_prekey (user_id, device_id, spk_id, spk_pub, spk_sig)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, device_id, spk_id)
		 DO UPDATE SET spk_pub = EXCLUDED.spk_pub, spk_sig = EXCLUDED.spk_sig, created_at = now()`,
		userID, b.DeviceID, b.SignedPreKey.ID, b.SignedPreKey.Pub, b.SignedPreKey.Sig); err != nil {
		return fmt.Errorf("upsert signed prekey: %w", err)
	}

	if err := insertOPKs(ctx, tx, userID, b.DeviceID, b.OneTimePreKeys); err != nil {
		return err
	}
	// NOTE: publishing a device must NOT delete the user's OTHER devices. A user may legitimately run
	// several (two browsers / phone + laptop); the client encrypts to ALL of them and each must keep
	// receiving decryptable copies. (Retiring others here broke multi-device delivery — a peer's message
	// went to only the last-published device while they read on another. Dead-device cleanup, if wanted,
	// belongs in a TTL/last-seen GC, not on publish.)
	return tx.Commit(ctx)
}

func (p *Postgres) AddOneTimePreKeys(ctx context.Context, userID, deviceID string, opks []PreKey) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM e2e_identity WHERE user_id = $1 AND device_id = $2)`,
		userID, deviceID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, ErrNotFound
	}
	// Purge spent one-time prekeys — consumed rows are never served and, with monotonic client ids, can
	// never be reissued, so keeping them only grows storage without bound as the device starts sessions.
	if _, err := tx.Exec(ctx,
		`DELETE FROM e2e_one_time_prekey WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NOT NULL`,
		userID, deviceID); err != nil {
		return 0, fmt.Errorf("purge consumed prekeys: %w", err)
	}
	// Cap the un-consumed pool: a well-behaved client tops up to ~20, so a device already at the ceiling
	// is a buggy/abusive replenish — skip inserting rather than let the pool grow without limit.
	var cur int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM e2e_one_time_prekey
		 WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL`,
		userID, deviceID).Scan(&cur); err != nil {
		return 0, err
	}
	if cur >= maxUnconsumedOPK {
		slog.Warn("one-time-prekey pool at cap; skipping replenish",
			"user", userID, "device", deviceID, "cap", maxUnconsumedOPK)
	} else if err := insertOPKs(ctx, tx, userID, deviceID, opks); err != nil {
		return 0, err
	}
	var remaining int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM e2e_one_time_prekey
		 WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL`,
		userID, deviceID).Scan(&remaining); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return remaining, nil
}

func insertOPKs(ctx context.Context, tx pgx.Tx, userID, deviceID string, opks []PreKey) error {
	if len(opks) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, o := range opks {
		batch.Queue(
			`INSERT INTO e2e_one_time_prekey (user_id, device_id, opk_id, opk_pub)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (user_id, device_id, opk_id) DO NOTHING`,
			userID, deviceID, o.ID, o.Pub)
	}
	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	inserted := 0
	for range opks {
		tag, err := br.Exec()
		if err != nil {
			return fmt.Errorf("insert one-time prekey: %w", err)
		}
		inserted += int(tag.RowsAffected())
	}
	// A dropped insert means the client reused an opk_id (ON CONFLICT DO NOTHING kept the old public key).
	// The invariant is "opk_id unique + monotonic per device forever" — a violation means the client's
	// private for that id no longer matches the served public, so X3DH under it will fail. Never silent.
	if inserted < len(opks) {
		slog.Warn("one-time-prekey id reuse: some publics dropped",
			"user", userID, "device", deviceID, "requested", len(opks), "inserted", inserted)
	}
	return nil
}

func (p *Postgres) FetchAndConsume(ctx context.Context, userID, deviceID string) ([]DeviceBundle, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Which devices to serve.
	var rows pgx.Rows
	if deviceID == "" {
		// Serve ALL of the user's devices — a user may run several, and the client encrypts to each so
		// every device gets a decryptable copy (multi-device delivery). (Do NOT serve only the latest:
		// that dropped messages for a peer reading on a different device.)
		rows, err = tx.Query(ctx,
			`SELECT device_id, identity_key_pub FROM e2e_identity WHERE user_id = $1 ORDER BY device_id`,
			userID)
	} else {
		rows, err = tx.Query(ctx,
			`SELECT device_id, identity_key_pub FROM e2e_identity WHERE user_id = $1 AND device_id = $2`,
			userID, deviceID)
	}
	if err != nil {
		return nil, err
	}
	type ident struct {
		device string
		ik     []byte
	}
	var idents []ident
	for rows.Next() {
		var it ident
		if err := rows.Scan(&it.device, &it.ik); err != nil {
			rows.Close()
			return nil, err
		}
		idents = append(idents, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(idents) == 0 {
		return nil, ErrNotFound
	}

	var out []DeviceBundle
	for _, it := range idents {
		bundle := DeviceBundle{DeviceID: it.device, IdentityKey: it.ik}

		// Current signed prekey = latest published for the device.
		var spk SignedPreKey
		err := tx.QueryRow(ctx,
			`SELECT spk_id, spk_pub, spk_sig FROM e2e_signed_prekey
			 WHERE user_id = $1 AND device_id = $2
			 ORDER BY created_at DESC, spk_id DESC LIMIT 1`,
			userID, it.device).Scan(&spk.ID, &spk.Pub, &spk.Sig)
		if errors.Is(err, pgx.ErrNoRows) {
			// No signed prekey → the bundle is unusable for X3DH; skip this device.
			continue
		}
		if err != nil {
			return nil, err
		}
		bundle.SignedPreKey = spk

		// Atomically consume the lowest un-consumed one-time prekey (may be none).
		var opk PreKey
		err = tx.QueryRow(ctx,
			`WITH picked AS (
			     SELECT opk_id FROM e2e_one_time_prekey
			     WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL
			     ORDER BY opk_id LIMIT 1
			     FOR UPDATE SKIP LOCKED
			 )
			 UPDATE e2e_one_time_prekey o SET consumed_at = now()
			 FROM picked
			 WHERE o.user_id = $1 AND o.device_id = $2 AND o.opk_id = picked.opk_id
			 RETURNING o.opk_id, o.opk_pub`,
			userID, it.device).Scan(&opk.ID, &opk.Pub)
		switch {
		case err == nil:
			bundle.OneTimePreKey = &opk
		case errors.Is(err, pgx.ErrNoRows):
			bundle.OneTimePreKey = nil // pool exhausted → SPK-only fallback
		default:
			return nil, err
		}

		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM e2e_one_time_prekey
			 WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL`,
			userID, it.device).Scan(&bundle.Remaining); err != nil {
			return nil, err
		}
		out = append(out, bundle)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (p *Postgres) CountOneTimePreKeys(ctx context.Context, userID, deviceID string) (int, error) {
	// Contract: an UNKNOWN user+device is ErrNotFound (not 0). The client's self-heal republish keys off
	// this 404 to detect a device the directory never registered (e.g. a first publish that failed while
	// the directory was unreachable). Returning 0 here — as a bare count would for a missing device —
	// silently disables that recovery path in prod. Mirror the Memory store.
	var exists bool
	if err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM e2e_identity WHERE user_id = $1 AND device_id = $2)`,
		userID, deviceID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, ErrNotFound
	}
	var n int
	err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM e2e_one_time_prekey
		 WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL`,
		userID, deviceID).Scan(&n)
	return n, err
}

func (p *Postgres) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	// The FK cascade drops the device's signed + one-time prekeys with the identity row.
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM e2e_identity WHERE user_id = $1 AND device_id = $2`,
		userID, deviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) PruneStaleDevices(ctx context.Context, olderThan time.Duration) (int, error) {
	// Delete a device only if it's stale AND the user has a newer one — so the most-recent device per user
	// is always kept (keep-newest), and a user never ends up with zero. updated_at is refreshed on every
	// publish/touch, so live devices survive and abandoned ones age out. FK cascade drops their prekeys.
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM e2e_identity e
		 WHERE e.updated_at < $1
		   AND EXISTS (SELECT 1 FROM e2e_identity n
		               WHERE n.user_id = e.user_id AND n.updated_at > e.updated_at)`,
		time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
