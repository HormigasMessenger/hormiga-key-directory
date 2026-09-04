-- ADR-023 §D5 — public-key directory for X3DH. Public keys ONLY.
-- Never stored: private keys, ratchet state, session keys, plaintext.

CREATE TABLE IF NOT EXISTS e2e_identity (
    user_id          text        NOT NULL,
    device_id        text        NOT NULL,
    identity_key_pub bytea       NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS e2e_signed_prekey (
    user_id    text        NOT NULL,
    device_id  text        NOT NULL,
    spk_id     integer     NOT NULL,
    spk_pub    bytea       NOT NULL,
    spk_sig    bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, spk_id),
    FOREIGN KEY (user_id, device_id)
        REFERENCES e2e_identity (user_id, device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS e2e_one_time_prekey (
    user_id     text        NOT NULL,
    device_id   text        NOT NULL,
    opk_id      integer     NOT NULL,
    opk_pub     bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz,
    PRIMARY KEY (user_id, device_id, opk_id),
    FOREIGN KEY (user_id, device_id)
        REFERENCES e2e_identity (user_id, device_id) ON DELETE CASCADE
);

-- Hot path: pick the lowest un-consumed one-time prekey for a device.
CREATE INDEX IF NOT EXISTS idx_opk_unconsumed
    ON e2e_one_time_prekey (user_id, device_id, opk_id)
    WHERE consumed_at IS NULL;
