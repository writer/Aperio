// google-workspace-oauth-sync pulls per-user OAuth grants from the Google
// Admin Directory tokens API and upserts them into security_assets +
// oauth_app_grants so the Shadow IT page stops showing zero OAuth apps
// for live tenants.
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/googleworkspaceoauthsync"
)

func main() {
	once := flag.Bool("once", false, "sync once and exit (useful for cron)")
	interval := flag.Duration("interval", 30*time.Minute, "sync interval between sweeps")
	flag.Parse()

	cfg := config.FromEnv()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
	db.SetConnMaxIdleTime(time.Duration(cfg.ConnMaxIdleMinutes) * time.Minute)

	sync := googleworkspaceoauthsync.New(db, resolverAdapter{base: bootstrap.GoogleOAuthResolver{DB: db}}).
		WithInterval(*interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := sync.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-oauth-sync: tick failed: %v", err)
		}
		return
	}
	log.Printf("google-workspace-oauth-sync: starting (interval=%s)", *interval)
	if err := sync.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-oauth-sync: %v", err)
	}
}

type resolverAdapter struct {
	base bootstrap.GoogleOAuthResolver
}

func (r resolverAdapter) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (googleworkspaceoauthsync.OAuthConfig, bool) {
	cfg, ok := r.base.ResolveGoogleOAuthClient(ctx, organizationID)
	if !ok {
		return googleworkspaceoauthsync.OAuthConfig{}, false
	}
	return googleworkspaceoauthsync.OAuthConfig{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}, true
}
