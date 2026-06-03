package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/postship/lowcode-role/internal/api"
	"github.com/postship/lowcode-role/internal/bundle"
	"github.com/postship/lowcode-role/internal/cache"
	"github.com/postship/lowcode-role/internal/config"
	"github.com/postship/lowcode-role/internal/db"
	"github.com/postship/lowcode-role/internal/opa"
	"github.com/postship/lowcode-role/internal/revision"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	basePath := os.Getenv("BASE_REGO_PATH")
	if basePath == "" {
		basePath = bundle.DefaultBaseRegoPath()
	}
	baseRego, err := bundle.LoadBaseRego(basePath)
	if err != nil {
		log.Fatalf("load base rego from %s: %v (set BASE_REGO_PATH)", basePath, err)
	}

	if err := os.MkdirAll(cfg.BundleOutDir, 0o755); err != nil {
		log.Fatalf("bundle dir: %v", err)
	}

	pub := &bundle.Publisher{
		Pool:     pool,
		OutDir:   cfg.BundleOutDir,
		BaseRego: baseRego,
		OPABin:   cfg.OPAExecutable,
	}

	if cfg.OPAExecutable == "" {
		log.Printf("warn: OPA CLI not found — compile/publish skip local `opa check` (runtime OPA sidecar still used for authorize)")
	}

	// Initial publish so OPA sidecar has data before first admin release.
	if _, _, err := pub.PublishAtomic(ctx); err != nil {
		log.Printf("warn: initial publish failed: %v", err)
	}

	revHolder := &revision.Holder{}
	var maxRev int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(revision),0) FROM policy_releases`).Scan(&maxRev); err != nil {
		log.Fatalf("revision: %v", err)
	}
	revHolder.Set(maxRev)

	srv := &api.Server{
		Pool:      pool,
		Pub:       pub,
		OPA:       opa.New(cfg.OPABaseURL),
		Rev:       revHolder,
		Cache:     cache.NewDecision(cfg.CacheTTL),
		OPABin:    cfg.OPAExecutable,
		BundleDir: cfg.BundleOutDir,
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
