// google-workspace-directory-sync pulls the Google Workspace user directory
// into saas_identities so the Security Graph, the executive report, and the
// Google Workspace assessment stop reporting 0 privileged identities / 0
// active accounts / 0% MFA coverage on real tenants. Until this command
// landed, the only producer of saas_identities was scripts/seed.ts (demo
// data); the live tables stayed empty after a Google connect even though
// the audit-log poller was already producing findings.
//
// Separated from cmd/google-workspace-poller because the two read different
// Google APIs (admin.reports vs admin.directory), have different rate
// limits, and progress on very different cadences. Coupling them would
// force the audit pipeline to wait through a Directory API outage.
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
	"github.com/writer/aperio/internal/googleworkspacedirectorysync"
)

func main() {
	once := flag.Bool("once", false, "sync once and exit (useful for cron)")
	interval := flag.Duration("interval", 15*time.Minute, "sync interval between sweeps")
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

	sync := googleworkspacedirectorysync.New(db, resolverAdapter{base: bootstrap.GoogleOAuthResolver{DB: db}}).
		WithInterval(*interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := sync.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-directory-sync: tick failed: %v", err)
		}
		return
	}
	log.Printf("google-workspace-directory-sync: starting (interval=%s)", *interval)
	if err := sync.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-directory-sync: %v", err)
	}
}

// resolverAdapter bridges bootstrap's local OAuthConfig type with the
// directory sync's OAuthConfig. They are structurally identical.
type resolverAdapter struct {
	base bootstrap.GoogleOAuthResolver
}

func (r resolverAdapter) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (googleworkspacedirectorysync.OAuthConfig, bool) {
	cfg, ok := r.base.ResolveGoogleOAuthClient(ctx, organizationID)
	if !ok {
		return googleworkspacedirectorysync.OAuthConfig{}, false
	}
	return googleworkspacedirectorysync.OAuthConfig{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}, true
}
