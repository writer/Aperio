package config

import (
	"os"
	"strings"
)

// Config contains the small runtime surface the Go service needs today. It is
// intentionally independent from the TypeScript API config so the new backend
// can be deployed, scaled, and rolled back as its own process.
type Config struct {
	// Addr is the HTTP listen address for the ConnectRPC server.
	Addr string
	// DatabaseURL points at the same Postgres database used by the TypeScript API.
	DatabaseURL string
	// WebOrigin is the single browser origin allowed to send credentialed RPCs.
	WebOrigin string
}

// FromEnv reads process configuration with local-development defaults. Required
// values, such as DATABASE_URL, are validated by cmd/aperio so tests can build a
// Config without a database.
func FromEnv() Config {
	return Config{
		Addr:        env("APERIO_CONNECT_ADDR", ":4100"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		WebOrigin:   strings.TrimRight(env("APERIO_WEB_ORIGIN", "http://localhost:3000"), "/"),
	}
}

// env returns a trimmed environment variable or a fallback when unset. Keeping
// trimming centralized prevents subtle CORS and listen-address mismatches.
func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
