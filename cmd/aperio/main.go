package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/bootstrap"
	"github.com/writer/aperio/internal/config"
)

func main() {
	cfg := config.FromEnv()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app := bootstrap.NewApp(cfg, db)
	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: app.Handler(),
	}
	log.Printf("Aperio Go Connect service listening on %s", cfg.Addr)
	log.Fatal(server.ListenAndServe())
}
