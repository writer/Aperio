package config

import (
	"os"
	"strings"
)

type Config struct {
	Addr        string
	DatabaseURL string
	WebOrigin   string
}

func FromEnv() Config {
	return Config{
		Addr:        env("APERIO_CONNECT_ADDR", ":4100"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		WebOrigin:   strings.TrimRight(env("APERIO_WEB_ORIGIN", "http://localhost:3000"), "/"),
	}
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
