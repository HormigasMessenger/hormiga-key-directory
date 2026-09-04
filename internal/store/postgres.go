package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	if err := insertOPKs(ctx, tx, userID, deviceID, opks); err != nil {
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
	for range opks {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert one-time prekey: %w", err)
		}
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
	var n int
	err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM e2e_one_time_prekey
		 WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL`,
		userID, deviceID).Scan(&n)
	return n, err
}
