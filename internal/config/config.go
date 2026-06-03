package config

import (
	"os"
	"os/exec"
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

func resolveOPAExecutable() string {
	raw := getenv("OPA_EXECUTABLE", "opa")
	if raw == "" {
		return ""
	}
	path, err := exec.LookPath(raw)
	if err != nil {
		if os.Getenv("OPA_EXECUTABLE") == "" {
			return ""
		}
		return raw
	}
	return path
}

func Load() Config {
	ttl := 200 * time.Millisecond
	if s := os.Getenv("ROLE_CACHE_TTL_MS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			ttl = time.Duration(n) * time.Millisecond
		}
	}
	return Config{
		DatabaseURL:   getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/lowcode_role?sslmode=disable"),
		ListenAddr:    getenv("LISTEN_ADDR", ":8080"),
		OPABaseURL:    getenv("OPA_BASE_URL", "http://127.0.0.1:8181"),
		BundleOutDir:  getenv("BUNDLE_OUT_DIR", "./.bundle/out"),
		OPAExecutable: resolveOPAExecutable(),
		CacheTTL:      ttl,
	}
}
