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
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
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
	// Spawn the LISTEN goroutine alongside the scheduled poller. It opens
	// its own pgx connection because database/sql does not expose the raw
	// Postgres notification channel needed for blocking LISTEN/NOTIFY.
	// Failures here log and exit the goroutine without taking down the
	// scheduled ticker, which still discovers new integrations on its
	// next sweep.
	go runSyncWakeListener(ctx, cfg.DatabaseURL, poller)

	log.Printf("google-workspace-poller: starting (interval=%s, wake-channel=%s)", *interval, bootstrap.GoogleWorkspaceSyncWakeChannel)
	if err := poller.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("google-workspace-poller: %v", err)
	}
}

// runSyncWakeListener opens a dedicated pgx connection, executes
// LISTEN on the wake channel, and dispatches WakeIntegration for each
// notification payload. On any connection error it logs, sleeps briefly
// to avoid tight reconnect loops, and retries until the parent context
// is cancelled.
func runSyncWakeListener(ctx context.Context, dsn string, poller *googleworkspacepoller.Poller) {
	const reconnectBackoff = 5 * time.Second
	channel := bootstrap.GoogleWorkspaceSyncWakeChannel
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			log.Printf("google-workspace-poller: listener connect failed: %v", err)
			sleepOrReturn(ctx, reconnectBackoff)
			continue
		}
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
			log.Printf("google-workspace-poller: LISTEN failed: %v", err)
			_ = conn.Close(ctx)
			sleepOrReturn(ctx, reconnectBackoff)
			continue
		}
		log.Printf("google-workspace-poller: listening on %s", channel)
		for {
			notification, waitErr := conn.WaitForNotification(ctx)
			if waitErr != nil {
				if ctx.Err() != nil {
					_ = conn.Close(ctx)
					return
				}
				log.Printf("google-workspace-poller: WaitForNotification failed: %v", waitErr)
				_ = conn.Close(ctx)
				break
			}
			integrationID := strings.TrimSpace(notification.Payload)
			if integrationID == "" {
				continue
			}
			// Run wake-ups in a goroutine so a slow Google API call cannot
			// stall the LISTEN loop and drop subsequent notifications.
			go func(id string) {
				if err := poller.WakeIntegration(ctx, id); err != nil {
					log.Printf("google-workspace-poller: wake integration %s failed: %v", id, err)
				}
			}(integrationID)
		}
	}
}

func sleepOrReturn(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
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
