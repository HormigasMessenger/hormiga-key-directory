package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// splitCSV parses a comma-separated env value into trimmed, non-empty entries.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Config is the full runtime configuration, sourced from the environment.
type Config struct {
	Addr             string // HTTP listen address
	DatabaseURL      string // Postgres DSN; empty + DevStub=true → in-memory store
	DevStub          bool   // use the in-memory store (dev/e2e only, like the messenger's StubClientDirectory)
	UserHeader       string // Oathkeeper-injected authenticated user id header (ADR-006)
	MaxOPKPerRequest int    // cap on one-time prekeys accepted per publish/replenish
	MaxKeyBytes      int    // per-key size sanity cap
	AutoMigrate      bool
	FetchRatePerMin  int    // per-caller KEY_FETCH budget (fetch consumes a peer's one-time prekey); 0 disables
	FetchBurst       int    // per-caller burst allowance for KEY_FETCH

	// Ephemeral TURN credentials (coturn use-auth-secret / TURN REST API). TurnSecret MUST equal coturn's
	// static-auth-secret. Empty TurnSecret disables the /v1/turn/credentials endpoint (503).
	TurnSecret string
	TurnURIs   []string // TURN URIs handed to the client, e.g. turn:host:3478?transport=udp
	TurnTTL    int      // credential lifetime in seconds
}

func FromEnv() (Config, error) {
	c := Config{
		Addr:             getenv("KD_ADDR", ":8092"),
		DatabaseURL:      os.Getenv("KD_DATABASE_URL"),
		DevStub:          getBool("KD_DEV_STUB", false),
		UserHeader:       getenv("KD_USER_HEADER", "X-User-Id"),
		MaxOPKPerRequest: getInt("KD_MAX_OPK_PER_REQUEST", 200),
		MaxKeyBytes:      getInt("KD_MAX_KEY_BYTES", 1024),
		AutoMigrate:      getBool("KD_AUTO_MIGRATE", true),
		FetchRatePerMin:  getInt("KD_FETCH_RATE_PER_MIN", 120),
		FetchBurst:       getInt("KD_FETCH_BURST", 30),
		TurnSecret:       os.Getenv("KD_TURN_SECRET"),
		TurnURIs:         splitCSV(os.Getenv("KD_TURN_URIS")),
		TurnTTL:          getInt("KD_TURN_TTL_SECONDS", 600),
	}
	if !c.DevStub && c.DatabaseURL == "" {
		return c, fmt.Errorf("KD_DATABASE_URL is required (or set KD_DEV_STUB=true for the in-memory store)")
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
