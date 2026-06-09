// google-workspace-poller pulls Google Workspace audit activities into the
// shared ingestion_jobs queue so the existing internal/ingestionworker rule
// evaluators can produce findings.
//
// This is a separate command from cmd/aperio so operators can scale OAuth
// quota usage independently from the API server and so a bug in the poller
// cannot bring down user-facing requests.
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
	"github.com/writer/aperio/internal/googleworkspacepoller"
)

func main() {
	once := flag.Bool("once", false, "tick once and exit (useful for cron)")
	interval := flag.Duration("interval", 60*time.Second, "poll interval between sweeps")
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

	// The bootstrap resolver reads per-tenant OAuth client rows (added in PR
	// #68) with an env-var fallback, so this command works without per-org
	// configuration as long as GOOGLE_WORKSPACE_CLIENT_ID/SECRET are set.
	poller := googleworkspacepoller.New(db, resolverAdapter{base: bootstrap.GoogleOAuthResolver{DB: db}}).
		WithInterval(*interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := poller.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-poller: tick failed: %v", err)
		}
		return
	}
	log.Printf("google-workspace-poller: starting (interval=%s)", *interval)
	if err := poller.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-poller: %v", err)
	}
}

// resolverAdapter bridges bootstrap's local poolerOAuthConfig type with the
// poller's OAuthConfig. They are structurally identical; the indirection
// just avoids forcing one package to import the other.
type resolverAdapter struct {
	base bootstrap.GoogleOAuthResolver
}

func (r resolverAdapter) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (googleworkspacepoller.OAuthConfig, bool) {
	cfg, ok := r.base.ResolveGoogleOAuthClient(ctx, organizationID)
	if !ok {
		return googleworkspacepoller.OAuthConfig{}, false
	}
	return googleworkspacepoller.OAuthConfig{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}, true
}
