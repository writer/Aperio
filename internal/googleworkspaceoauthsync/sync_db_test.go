package googleworkspaceoauthsync

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDBPruneStaleOauthGrantsRemovesRevokedApps(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed OAuth sync tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	ctx := context.Background()
	suffix := shortHash(t.Name() + time.Now().UTC().String())
	orgID := "org_oauth_prune_" + suffix
	integrationID := "int_oauth_prune_" + suffix
	currentAssetID := "ast_oauth_current_" + suffix
	staleAssetID := "ast_oauth_stale_" + suffix
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)

	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, orgID, "OAuth prune", "oauth-prune-"+suffix); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	if _, err := db.ExecContext(ctx, `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, status, mode, created_at, updated_at
		) VALUES (
			$1, $2, 'GOOGLE_WORKSPACE'::"SaaSProvider", 'Google Workspace', 'example.com',
			ARRAY[]::text[], ARRAY[]::text[], 'test-token-envelope',
			'CONNECTED'::"IntegrationStatus", 'READ_ONLY'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID); err != nil {
		t.Fatalf("seed integration: %v", err)
	}
	for _, asset := range []struct {
		id       string
		clientID string
		seenAt   time.Time
	}{
		{currentAssetID, "current-client", now},
		{staleAssetID, "stale-client", old},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO security_assets (
				id, organization_id, integration_id, type, provider, external_id, name,
				labels, criticality, exposure_level, ownership_status, contains_sensitive_data,
				is_privileged, risk_score, last_observed_at, created_at, updated_at
			) VALUES (
				$1, $2, $3, 'OAUTH_APP'::"SecurityAssetType", 'GOOGLE_WORKSPACE'::"SaaSProvider",
				$4, $5, ARRAY['shadow-it']::text[], 'MEDIUM'::"AssetCriticality",
				'TRUSTED_EXTERNAL'::"AssetExposureLevel", 'UNASSIGNED'::"AssetOwnershipStatus",
				false, false, 0, $6, NOW(), NOW()
			)
		`, asset.id, orgID, integrationID, asset.clientID, asset.clientID, asset.seenAt); err != nil {
			t.Fatalf("seed asset %s: %v", asset.clientID, err)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO oauth_app_grants (
				id, organization_id, integration_id, asset_id, provider, external_app_id,
				app_display_name, user_email, scopes, anonymous, native_app, last_observed_at,
				created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, 'GOOGLE_WORKSPACE'::"SaaSProvider", $5,
				$6, $7, ARRAY['scope']::text[], false, false, $8, NOW(), NOW()
			)
		`, "grant_"+asset.clientID+"_"+suffix, orgID, integrationID, asset.id, asset.clientID, asset.clientID, asset.clientID+"@example.com", asset.seenAt); err != nil {
			t.Fatalf("seed grant %s: %v", asset.clientID, err)
		}
	}

	s := &Sync{db: db}
	if err := s.pruneStaleOauthGrants(ctx, integrationRow{ID: integrationID, OrganizationID: orgID}, now); err != nil {
		t.Fatalf("prune stale grants: %v", err)
	}
	assertOAuthPruneCount(t, db, `SELECT COUNT(*) FROM oauth_app_grants WHERE id = $1`, "grant_current-client_"+suffix, 1)
	assertOAuthPruneCount(t, db, `SELECT COUNT(*) FROM oauth_app_grants WHERE id = $1`, "grant_stale-client_"+suffix, 0)
	assertOAuthPruneCount(t, db, `SELECT COUNT(*) FROM security_assets WHERE id = $1`, currentAssetID, 1)
	assertOAuthPruneCount(t, db, `SELECT COUNT(*) FROM security_assets WHERE id = $1`, staleAssetID, 0)
}

func TestDBUpsertOauthAssetUpgradesScopeRisk(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed OAuth sync tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	ctx := context.Background()
	suffix := shortHash(t.Name() + time.Now().UTC().String())
	orgID := "org_oauth_risk_" + suffix
	integrationID := "int_oauth_risk_" + suffix
	now := time.Date(2026, 6, 11, 13, 0, 0, 0, time.UTC)
	if _, err := db.ExecContext(ctx, `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, orgID, "OAuth risk", "oauth-risk-"+suffix); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	if _, err := db.ExecContext(ctx, `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, status, mode, created_at, updated_at
		) VALUES (
			$1, $2, 'GOOGLE_WORKSPACE'::"SaaSProvider", 'Google Workspace', 'example.com',
			ARRAY[]::text[], ARRAY[]::text[], 'test-token-envelope',
			'CONNECTED'::"IntegrationStatus", 'READ_ONLY'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID); err != nil {
		t.Fatalf("seed integration: %v", err)
	}

	s := &Sync{db: db}
	integ := integrationRow{ID: integrationID, OrganizationID: orgID}
	assetID, err := s.upsertOauthAsset(ctx, integ, parsedToken{ClientID: "critical-client", Label: "Critical Client", Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatalf("initial upsert oauth asset: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE security_assets
		SET criticality = 'LOW'::"AssetCriticality", contains_sensitive_data = false, is_privileged = false, risk_score = 0
		WHERE id = $1 AND organization_id = $2
	`, assetID, orgID); err != nil {
		t.Fatalf("downgrade existing asset: %v", err)
	}
	if _, err := s.upsertOauthAsset(ctx, integ, parsedToken{ClientID: "critical-client", Label: "Critical Client", Scopes: []string{"https://mail.google.com/", "https://www.googleapis.com/auth/admin.directory.user.readonly"}}, now.Add(time.Minute)); err != nil {
		t.Fatalf("risk upgrade upsert oauth asset: %v", err)
	}

	var criticality string
	var containsSensitive, isPrivileged bool
	var riskScore int
	if err := db.QueryRowContext(ctx, `
		SELECT criticality::text, contains_sensitive_data, is_privileged, risk_score
		FROM security_assets
		WHERE id = $1 AND organization_id = $2
	`, assetID, orgID).Scan(&criticality, &containsSensitive, &isPrivileged, &riskScore); err != nil {
		t.Fatalf("query upgraded asset risk: %v", err)
	}
	if criticality != "CRITICAL" || !containsSensitive || !isPrivileged || riskScore < 92 {
		t.Fatalf("upgraded asset risk = criticality=%s sensitive=%t privileged=%t risk=%d", criticality, containsSensitive, isPrivileged, riskScore)
	}
}

func assertOAuthPruneCount(t *testing.T, db *sql.DB, query string, arg any, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), query, arg).Scan(&got); err != nil {
		t.Fatalf("count with %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("count with %q = %d, want %d", query, got, want)
	}
}
