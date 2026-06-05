package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
)

// main is the production entrypoint for the Go/ConnectRPC backend. It is kept
// separate from the existing Express server so Aperio can shift read paths to Go
// incrementally while both runtimes share Postgres and cookie sessions.
func main() {
	cfg := config.FromEnv()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	// pgx's stdlib driver gives database/sql pooling while keeping the codebase
	// ready for lower-level pgx usage as more endpoints move to Go.
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app := bootstrap.NewApp(cfg, db)
	// The service intentionally uses the standard net/http server that ConnectRPC
	// generates handlers for; this mirrors Cerebro's lightweight server wiring.
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Aperio Go Connect service listening on %s", cfg.Addr)
	log.Fatal(server.ListenAndServe())
}
