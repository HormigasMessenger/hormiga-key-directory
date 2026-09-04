# hormiga-key-directory

Standalone, Kratos-anchored **E2E public-key directory** for Hormigas Messenger.
Prekey server for the **X3DH** handshake (Signal protocol) — it stores and serves
**public** keys only and does **no cryptography**. All X3DH / Double Ratchet math
runs on the clients; this service is public-key CRUD + a transactional one-time-prekey
consume.

Decision of record: **ADR-023** (`messenger E2E secret threads`) + its addendum
`ADR-023-addendum-key-directory-standalone-service` (placement: standalone, beside IDS;
stack: Go; zero runtime coupling to the messenger).

## What it is (and is NOT)

- **IS:** a directory of each device's public identity key, signed prekey (+signature),
  and a pool of one-time prekeys; hands a peer a prekey *bundle* to start an offline X3DH
  session, consuming one one-time prekey atomically.
- **IS NOT:** a crypto engine. It never holds a private key, ratchet state, session key
  or plaintext. It does not relay messages — the encrypted `E2E_MSG` rides the messenger's
  existing opaque delivery path, never this service.

## Trust model (read this)

- **Auth:** the service trusts the Oathkeeper-injected `X-User-Id` header (ADR-006). It
  **must be network-isolated** so only the proxy sets that header — a directly reachable
  instance makes it forgeable.
- **Publish** binds a device to the authenticated caller's `userId` — you can only publish
  under your own identity.
- **Fetch** returns any peer's *public* bundle. The MITM risk lives at fetch and is **not**
  closed by this service or by auth — only client-side **safety numbers** close it
  (ADR-023 §D7). This service is a *trusted* key distributor by construction.

## API

All `/v1` routes require the injected identity header.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/keys` | **KEY_PUBLISH** — register device identity + signed prekey, seed OPK pool (caller's own id) |
| `POST` | `/v1/keys/one-time` | replenish the caller's device OPK pool |
| `GET`  | `/v1/keys/self/count?deviceId=…` | caller's remaining OPKs (low-water check) |
| `GET`  | `/v1/keys/{userId}` | **KEY_FETCH** — bundles for every device of a peer (consumes one OPK/device) |
| `GET`  | `/v1/keys/{userId}/{deviceId}` | **KEY_FETCH** — one device's bundle |
| `GET`  | `/healthz`, `/readyz` | liveness / readiness (unauthenticated) |

Public keys are base64 (std). Fetch returns `oneTimePreKey: null` when the pool is
exhausted (X3DH falls back to SPK-only, ADR-023 §D5); `oneTimePreKeysRemaining` drives
client replenishment.

### Publish example

```json
POST /v1/keys      (X-User-Id: alice)
{
  "deviceId": "b3b1…-uuid",
  "identityKey": "<base64 pub>",
  "signedPreKey": { "id": 1, "publicKey": "<base64>", "signature": "<base64>" },
  "oneTimePreKeys": [ { "id": 100, "publicKey": "<base64>" }, { "id": 101, "publicKey": "<base64>" } ]
}
```

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `KD_ADDR` | `:8092` | listen address |
| `KD_DATABASE_URL` | — | Postgres DSN (required unless `KD_DEV_STUB=true`) |
| `KD_DEV_STUB` | `false` | in-memory store for dev/e2e (not persistent) |
| `KD_USER_HEADER` | `X-User-Id` | Oathkeeper-injected identity header |
| `KD_MAX_OPK_PER_REQUEST` | `200` | cap on OPKs per publish/replenish |
| `KD_MAX_KEY_BYTES` | `1024` | per-key size sanity cap |
| `KD_AUTO_MIGRATE` | `true` | run embedded migrations at startup |

## Run

```bash
# dev, no database
KD_DEV_STUB=true go run ./cmd/keydirectory

# with Postgres
KD_DATABASE_URL='postgres://user:pass@localhost:5432/hormiga_keys' go run ./cmd/keydirectory

go test ./...        # unit tests over the in-memory store
```

Real-Postgres integration test: set `KD_TEST_DATABASE_URL` (else it is skipped).

## Oathkeeper (deploy note)

Put this service behind Oathkeeper like the rest: strip client-supplied `X-User-Id`,
authenticate the Kratos session (`/sessions/whoami`), inject `X-User-Id`, and keep the
service unreachable except via the proxy (ADR-006).
