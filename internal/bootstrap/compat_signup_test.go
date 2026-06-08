package bootstrap

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/writer/aperio/internal/config"
)

// newSignupTestDB opens a Postgres connection for the signup tests but does
// NOT pre-seed an organization the way newTestDBApp does. Signup creates its
// own organization, so any pre-existing row would only get in the way.
func newSignupTestDB(t *testing.T) *App {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed route tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	t.Cleanup(func() { _ = db.Close() })
	return NewApp(config.Config{WebOrigin: "http://localhost:3000", SessionIdleMinutes: 120}, db)
}

func TestCompatSignupSucceeds(t *testing.T) {
	app := newSignupTestDB(t)
	slug := "signup-" + strings.ToLower(randomBase36(10))
	email := "owner-" + strings.ToLower(randomBase36(8)) + "@example.com"
	t.Cleanup(func() {
		_, _ = app.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE slug = $1`, slug)
	})

	out, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Signup Test",
		"organizationSlug": slug,
		"ownerEmail":       email,
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{})
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	data := dataMap(t, out)
	if data["token"] == "" || data["organization"] == nil || data["user"] == nil {
		t.Fatalf("expected populated signup payload, got %#v", data)
	}
}

func TestCompatSignupReturnsAlreadyExistsForDuplicateSlug(t *testing.T) {
	app := newSignupTestDB(t)
	slug := "dup-" + strings.ToLower(randomBase36(10))
	t.Cleanup(func() {
		_, _ = app.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE slug = $1`, slug)
	})

	if _, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Duplicate Test",
		"organizationSlug": slug,
		"ownerEmail":       "first-" + strings.ToLower(randomBase36(8)) + "@example.com",
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{}); err != nil {
		t.Fatalf("first signup failed: %v", err)
	}

	_, err := app.compatSignup(context.Background(), map[string]any{
		"organizationName": "Duplicate Test",
		"organizationSlug": slug,
		"ownerEmail":       "second-" + strings.ToLower(randomBase36(8)) + "@example.com",
		"password":         "Sup3rSecretPassphrase!",
	}, http.Header{})
	if err == nil {
		t.Fatal("expected duplicate-slug signup to error")
	}
	if code := connect.CodeOf(err); code != connect.CodeAlreadyExists {
		// A regression that drops the unique-violation guard would surface
		// here as CodeInternal with a 25P02 message, which is exactly the
		// confusing experience we are protecting against.
		t.Fatalf("expected CodeAlreadyExists, got %v (%v)", code, err)
	}
	if !strings.Contains(err.Error(), "workspace slug is already in use") {
		t.Fatalf("expected friendly slug-collision message, got %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "25p02") ||
		strings.Contains(strings.ToLower(err.Error()), "current transaction is aborted") {
		t.Fatalf("signup leaked the SQLSTATE 25P02 footgun: %v", err)
	}
}
