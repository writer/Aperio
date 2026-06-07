package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/mcpbroker"
)

func main() {
	log.SetOutput(os.Stderr)
	cfg := config.FromEnv()
	var db *sql.DB
	if cfg.DatabaseURL != "" {
		opened, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			log.Fatal(err)
		}
		db = opened
		defer db.Close()
		db.SetMaxOpenConns(cfg.MaxOpenConns)
		db.SetMaxIdleConns(cfg.MaxIdleConns)
		db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
		db.SetConnMaxIdleTime(time.Duration(cfg.ConnMaxIdleMinutes) * time.Minute)
	}

	server := mcpbroker.NewServer(mcpbroker.NewToolService(db))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		if db != nil {
			_ = db.Close()
		}
		os.Exit(0)
	}()
	ctx := context.Background()
	if err := server.Run(ctx, os.Stdin, os.Stdout); err != nil {
		log.Printf("MCP broker stopped: %v", err)
	}
}
