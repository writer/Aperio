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
	"github.com/writer/aperio/internal/ingestionworker"
)

func main() {
	once := flag.Bool("once", false, "drain once and exit")
	limit := flag.Int("limit", 25, "maximum jobs to claim per drain")
	interval := flag.Duration("interval", 5*time.Second, "poll interval")
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

	worker := ingestionworker.New(db)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		result, err := worker.Drain(ctx, *limit)
		if err != nil {
			log.Printf("ingestion drain failed: %v", err)
		} else if result.Processed > 0 {
			log.Printf("ingestion drain processed=%d succeeded=%d failed=%d", result.Processed, result.Succeeded, result.Failed)
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
