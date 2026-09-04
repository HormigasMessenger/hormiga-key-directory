package api

// Wire DTOs. Public key material travels as standard base64 strings.

type PreKeyDTO struct {
	ID        int32  `json:"id"`
	PublicKey string `json:"publicKey"`
}

type SignedPreKeyDTO struct {
	ID        int32  `json:"id"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// PublishRequest is the KEY_PUBLISH body. userId is taken from the authenticated
// header, never the body — a client can only publish under its own identity.
type PublishRequest struct {
	DeviceID       string          `json:"deviceId"`
	IdentityKey    string          `json:"identityKey"`
	SignedPreKey   SignedPreKeyDTO `json:"signedPreKey"`
	OneTimePreKeys []PreKeyDTO     `json:"oneTimePreKeys"`
}

// ReplenishRequest tops up a device's one-time prekey pool.
type ReplenishRequest struct {
	DeviceID       string      `json:"deviceId"`
	OneTimePreKeys []PreKeyDTO `json:"oneTimePreKeys"`
}

type DeviceBundleDTO struct {
	DeviceID                string          `json:"deviceId"`
	IdentityKey             string          `json:"identityKey"`
	SignedPreKey            SignedPreKeyDTO `json:"signedPreKey"`
	OneTimePreKey           *PreKeyDTO      `json:"oneTimePreKey"` // null when the pool is exhausted
	OneTimePreKeysRemaining int             `json:"oneTimePreKeysRemaining"`
}

// FetchResponse is the KEY_FETCH result — one entry per usable device.
type FetchResponse struct {
	UserID  string            `json:"userId"`
	Devices []DeviceBundleDTO `json:"devices"`
}

type PublishResponse struct {
	DeviceID                string `json:"deviceId"`
	OneTimePreKeysRemaining int    `json:"oneTimePreKeysRemaining"`
}

type CountResponse struct {
	DeviceID                string `json:"deviceId"`
	OneTimePreKeysRemaining int    `json:"oneTimePreKeysRemaining"`
}
