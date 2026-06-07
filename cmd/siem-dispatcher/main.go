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
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/siemdispatcher"
)

func main() {
	once := flag.Bool("once", false, "drain once and exit")
	limit := flag.Int("limit", 25, "maximum deliveries to claim per drain")
	interval := flag.Duration("interval", 5*time.Second, "poll interval")
	organizationID := flag.String("organization", "", "optional organization scope for local validation")
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

	dispatcher := siemdispatcher.New(db)
	if *organizationID != "" {
		dispatcher.SetOrganizationScope(*organizationID)
	}
	if enabled, err := siemdispatcher.EnableLocalCaptureFromEnv(dispatcher); err != nil {
		log.Fatal(err)
	} else if enabled {
		log.Print("SIEM local capture smoke transport enabled")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		result, err := dispatcher.Drain(ctx, *limit)
		if err != nil {
			log.Printf("SIEM drain failed: %v", err)
		} else if result.Processed > 0 {
			log.Printf("SIEM drain processed=%d delivered=%d failed=%d", result.Processed, result.Delivered, result.Failed)
		}
		if *once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}
