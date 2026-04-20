package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL   string
	ListenAddr    string
	OPABaseURL    string
	BundleOutDir  string
	OPAExecutable string
	CacheTTL      time.Duration
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func Load() Config {
	ttl := 200 * time.Millisecond
	if s := os.Getenv("AUTHZ_CACHE_TTL_MS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			ttl = time.Duration(n) * time.Millisecond
		}
	}
	return Config{
		DatabaseURL:   getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/authz?sslmode=disable"),
		ListenAddr:    getenv("LISTEN_ADDR", ":8080"),
		OPABaseURL:    getenv("OPA_BASE_URL", "http://127.0.0.1:8181"),
		BundleOutDir:  getenv("BUNDLE_OUT_DIR", "./.bundle/out"),
		OPAExecutable: getenv("OPA_EXECUTABLE", "opa"),
		CacheTTL:      ttl,
	}
}
