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
	"errors"
	"flag"
	"fmt"
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

// onceDrainWindow bounds how long the -once entrypoint waits for buffered
// wake-up notifications after its single Tick completes. Notifications fired
// from compatCreateIntegration / the OAuth callback during the Tick land on
// the LISTEN connection's server-side queue, so the drain window only needs
// to be long enough for WaitForNotification to surface anything already
// buffered. Keeping it short (a couple of seconds) preserves the "useful
// for cron" semantics of -once.
const onceDrainWindow = 2 * time.Second

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
		// Establish LISTEN *before* the Tick so any pg_notify wake-up fired
		// from compatCreateIntegration / the Google OAuth callback during
		// the Tick is queued server-side and surfaced when we drain after.
		// Cron-style deployments (npm run worker:google -- -once) would
		// otherwise silently drop every wake-up, leaving newly connected
		// Google Workspace tenants waiting for the next scheduled cron run.
		listener, listenErr := openSyncWakeListener(ctx, cfg.DatabaseURL)
		if listenErr != nil {
			log.Printf("google-workspace-poller: -once listener setup failed (immediate wake-ups will be dropped): %v", listenErr)
		} else {
			defer listener.Close(context.Background())
		}
		if err := poller.Tick(ctx); err != nil {
			log.Fatalf("google-workspace-poller: tick failed: %v", err)
		}
		if listener != nil {
			drainCtx, cancel := context.WithTimeout(ctx, onceDrainWindow)
			dispatchSyncWakes(drainCtx, listener, poller)
			cancel()
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

// openSyncWakeListener opens a dedicated pgx connection and runs LISTEN on
// the wake channel. Returned to the caller so it can pump notifications via
// dispatchSyncWakes. Caller is responsible for closing the connection.
func openSyncWakeListener(ctx context.Context, dsn string) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("listener connect: %w", err)
	}
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{bootstrap.GoogleWorkspaceSyncWakeChannel}.Sanitize()); err != nil {
		_ = conn.Close(context.Background())
		return nil, fmt.Errorf("LISTEN %s: %w", bootstrap.GoogleWorkspaceSyncWakeChannel, err)
	}
	return conn, nil
}

// dispatchSyncWakes pumps notifications off the listener and dispatches
// Poller.WakeIntegration per payload until the provided context is done or
// the connection drops. Each wake-up runs in its own goroutine so a slow
// Google API call cannot stall subsequent notifications. Returns silently
// when ctx is cancelled (including the deadline-driven -once drain) and
// returns on any non-context error so the caller can decide whether to
// reconnect.
func dispatchSyncWakes(ctx context.Context, conn *pgx.Conn, poller *googleworkspacepoller.Poller) {
	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			log.Printf("google-workspace-poller: WaitForNotification failed: %v", err)
			return
		}
		integrationID := strings.TrimSpace(notification.Payload)
		if integrationID == "" {
			continue
		}
		go func(id string) {
			if err := poller.WakeIntegration(ctx, id); err != nil {
				log.Printf("google-workspace-poller: wake integration %s failed: %v", id, err)
			}
		}(integrationID)
	}
}

// runSyncWakeListener is the long-running variant used by the daemon mode.
// It transparently reconnects on connection-level failures so a transient
// Postgres restart does not silently drop future wake-ups for the rest of
// the process lifetime.
func runSyncWakeListener(ctx context.Context, dsn string, poller *googleworkspacepoller.Poller) {
	const reconnectBackoff = 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := openSyncWakeListener(ctx, dsn)
		if err != nil {
			log.Printf("google-workspace-poller: %v", err)
			sleepOrReturn(ctx, reconnectBackoff)
			continue
		}
		log.Printf("google-workspace-poller: listening on %s", bootstrap.GoogleWorkspaceSyncWakeChannel)
		dispatchSyncWakes(ctx, conn, poller)
		_ = conn.Close(context.Background())
		if ctx.Err() != nil {
			return
		}
		// dispatchSyncWakes returned for a non-context reason (connection
		// drop, server-side LISTEN reset). Back off briefly and reconnect
		// so wake-ups continue to flow.
		sleepOrReturn(ctx, reconnectBackoff)
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
