package bootstrap

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/config"
)

// newTestDBApp wires an App against a real Postgres instance. The tests are
// skipped unless APERIO_TEST_DATABASE_URL points at a migrated database, so the
// default `go test ./...` run stays hermetic while CI can exercise the full
// SQL-backed compatibility routes.
func newTestDBApp(t *testing.T) (*App, compatAuth) {
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

	orgID := compatID("org")
	slug := "test-" + strings.ToLower(randomBase36(12))
	if _, err := db.ExecContext(context.Background(), `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, orgID, "Test Org", slug); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
		_ = db.Close()
	})

	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, db)
	auth := compatAuth{OrganizationID: orgID, UserID: compatID("usr"), Email: "admin@example.com", Role: "ADMIN"}
	return app, auth
}

func dataMap(t *testing.T, result any) map[string]any {
	t.Helper()
	envelope, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %T", envelope["data"])
	}
	return data
}

func TestDBIntegrationLifecycle(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	const plaintextToken = "xoxb-example-access-token-1234567890"
	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Prod",
		"externalAccountId": "T123456",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": plaintextToken},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	var dbProvider string
	var scopesJSON string
	var encryptedAccess string
	if err := app.db.QueryRowContext(ctx, `SELECT provider::text, array_to_json(scopes)::text, encrypted_access_token FROM integration_connections WHERE id = $1 AND organization_id = $2`, integrationID, auth.OrganizationID).Scan(&dbProvider, &scopesJSON, &encryptedAccess); err != nil {
		t.Fatalf("query integration: %v", err)
	}
	if dbProvider != "SLACK" {
		t.Fatalf("provider = %s, want SLACK", dbProvider)
	}
	var scopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
		t.Fatalf("decode scopes: %v", err)
	}
	if len(scopes) == 0 {
		t.Fatal("expected catalog scopes to be persisted")
	}
	if strings.Contains(encryptedAccess, plaintextToken) {
		t.Fatal("access token persisted in plaintext")
	}

	checks := dataMap(t, mustCall(t, func() (any, error) { return app.compatIntegrationChecks(ctx, integrationID, auth) }))
	if checks["integrationId"].(string) != integrationID {
		t.Fatalf("checks integrationId = %v", checks["integrationId"])
	}

	const disabledCheck = "slack.mfa_disabled"
	updated := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateIntegrationChecks(ctx, integrationID, map[string]any{"disabledChecks": []any{disabledCheck}}, auth)
	}))
	disabled, _ := updated["disabledChecks"].([]string)
	if len(disabled) != 1 || disabled[0] != disabledCheck {
		t.Fatalf("disabledChecks = %v", updated["disabledChecks"])
	}
	var persistedDisabledJSON string
	if err := app.db.QueryRowContext(ctx, `SELECT array_to_json(disabled_checks)::text FROM integration_connections WHERE id = $1`, integrationID).Scan(&persistedDisabledJSON); err != nil {
		t.Fatalf("query disabled checks: %v", err)
	}
	var persistedDisabled []string
	if err := json.Unmarshal([]byte(persistedDisabledJSON), &persistedDisabled); err != nil {
		t.Fatalf("decode disabled checks: %v", err)
	}
	if len(persistedDisabled) != 1 || persistedDisabled[0] != disabledCheck {
		t.Fatalf("persisted disabled checks = %v", persistedDisabled)
	}

	if _, err := app.compatForceSync(ctx, integrationID, auth); err == nil {
		t.Fatal("expected Slack force sync to be unsupported")
	}

	if _, err := app.compatDeleteIntegration(ctx, integrationID, auth); err != nil {
		t.Fatalf("delete integration: %v", err)
	}
	var remaining int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM integration_connections WHERE id = $1`, integrationID).Scan(&remaining); err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatal("expected integration to be deleted")
	}
}

func TestDBSiemLifecycle(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	const plaintextToken = "splunk-hec-example-token-1234567890"
	created, err := app.compatCreateSiem(ctx, map[string]any{
		"kind":        "SPLUNK_HEC",
		"name":        "Splunk",
		"endpointUrl": "https://8.8.8.8/services/collector",
		"streams":     []any{"FINDINGS"},
		"token":       plaintextToken,
	}, auth)
	if err != nil {
		t.Fatalf("create siem: %v", err)
	}
	destinationID := dataMap(t, created)["id"].(string)

	var encryptedToken sql.NullString
	var kind string
	if err := app.db.QueryRowContext(ctx, `SELECT kind::text, encrypted_token FROM siem_destinations WHERE id = $1 AND organization_id = $2`, destinationID, auth.OrganizationID).Scan(&kind, &encryptedToken); err != nil {
		t.Fatalf("query siem destination: %v", err)
	}
	if kind != "SPLUNK_HEC" {
		t.Fatalf("kind = %s, want SPLUNK_HEC", kind)
	}
	if !encryptedToken.Valid || encryptedToken.String == "" {
		t.Fatal("expected encrypted token to be stored")
	}
	if strings.Contains(encryptedToken.String, plaintextToken) {
		t.Fatal("siem token persisted in plaintext")
	}

	if _, err := app.compatTestSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("test siem: %v", err)
	}
	var deliveryStatus string
	if err := app.db.QueryRowContext(ctx, `SELECT status::text FROM siem_deliveries WHERE destination_id = $1`, destinationID).Scan(&deliveryStatus); err != nil {
		t.Fatalf("query siem delivery: %v", err)
	}
	if deliveryStatus != "PENDING" {
		t.Fatalf("delivery status = %s, want PENDING", deliveryStatus)
	}

	if _, err := app.compatDeleteSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("delete siem: %v", err)
	}
	var remaining int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM siem_destinations WHERE id = $1`, destinationID).Scan(&remaining); err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatal("expected siem destination to be deleted")
	}
}

func TestDBSlackRemediationUsesDecryptedToken(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	auth.UserID = ""

	const plaintextToken = "xoxp-remediation-secret"
	var providerCalls int
	var findingID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		var requestedAuditRows int
		if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedAuditRows); err != nil {
			t.Fatalf("query requested audit rows before provider call: %v", err)
		}
		if requestedAuditRows != 1 {
			t.Fatalf("expected requested audit before provider call, got %d", requestedAuditRows)
		}
		if r.URL.Path != "/admin.apps.uninstall" {
			t.Fatalf("path = %s, want /admin.apps.uninstall", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+plaintextToken {
			t.Fatalf("authorization header = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("app_id"); got != "A123" {
			t.Fatalf("app_id = %q", got)
		}
		if got := r.Form.Get("team_id"); got != "T123456" {
			t.Fatalf("team_id = %q", got)
		}
		w.Header().Set("X-Slack-Req-Id", "slack-db-route-req")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Remediation",
		"externalAccountId": "T123456",
		"mode":              "REMEDIATION",
		"credentials":       map[string]any{"accessToken": plaintextToken},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	findingID = compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, "Suspicious Slack app", "seeded for remediation test", json.RawMessage(`{"subject":"A123"}`)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	result := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install", "targetIdentifier": "A123"}, auth)
	}))
	if result["success"] != true {
		t.Fatalf("expected remediation success, got %v", result)
	}
	if result["providerRequestId"] != "slack-db-route-req" {
		t.Fatalf("providerRequestId = %v", result["providerRequestId"])
	}
	if providerCalls != 1 {
		t.Fatalf("expected one provider call, got %d", providerCalls)
	}

	var status string
	if err := app.db.QueryRowContext(ctx, `SELECT status::text FROM security_findings WHERE id = $1`, findingID).Scan(&status); err != nil {
		t.Fatalf("query finding status: %v", err)
	}
	if status != "RESOLVED" {
		t.Fatalf("finding status = %s, want RESOLVED", status)
	}
	var auditMetadata string
	if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.success'`, auth.OrganizationID, findingID).Scan(&auditMetadata); err != nil {
		t.Fatalf("query remediation audit metadata: %v", err)
	}
	if strings.Contains(auditMetadata, plaintextToken) {
		t.Fatal("audit metadata leaked the Slack access token")
	}
	if !strings.Contains(auditMetadata, "slack-db-route-req") {
		t.Fatalf("audit metadata missing provider request id: %s", auditMetadata)
	}
	var requestedMetadata string
	if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedMetadata); err != nil {
		t.Fatalf("query requested audit metadata: %v", err)
	}
	if strings.Contains(requestedMetadata, plaintextToken) {
		t.Fatal("requested audit metadata leaked the Slack access token")
	}
}

func TestDBSlackRemediationRequiresExplicitAppID(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	auth.UserID = ""

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Remediation",
		"externalAccountId": "T123456",
		"mode":              "REMEDIATION",
		"credentials":       map[string]any{"accessToken": "xoxp-remediation-secret"},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	findingID := compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, "Slack user finding", "seeded for remediation test", json.RawMessage(`{"subject":"user@example.com"}`)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	_, err = app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install"}, auth)
	if err == nil {
		t.Fatal("expected missing Slack app id to reject")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
	}
	if providerCalls != 0 {
		t.Fatalf("expected no provider calls, got %d", providerCalls)
	}
	var requestedRows int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedRows); err != nil {
		t.Fatalf("count requested audit rows: %v", err)
	}
	if requestedRows != 0 {
		t.Fatalf("expected no requested audit for rejected request, got %d", requestedRows)
	}
}

func TestDBGoogleMailboxScanConfig(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "GOOGLE_WORKSPACE",
		"displayName":       "Google Workspace",
		"externalAccountId": "example.com",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "google-example-access-token-1234567890"},
	}, auth)
	if err != nil {
		t.Fatalf("create google integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	auditAuth := auth
	auditAuth.UserID = ""
	const clientEmail = "mailbox-scanner@example.com"
	const privateKey = "example-google-mailbox-private-key-value-1234567890"
	enabled := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
			"enabled":                   true,
			"serviceAccountClientEmail": clientEmail,
			"privateKey":                privateKey,
		}, auditAuth)
	}))
	if enabled["enabled"] != true || enabled["serviceAccountClientEmail"] != clientEmail {
		t.Fatalf("unexpected enabled config: %v", enabled)
	}

	var encryptedKey string
	if err := app.db.QueryRowContext(ctx, `SELECT encrypted_google_mailbox_scan_private_key FROM integration_connections WHERE id = $1`, integrationID).Scan(&encryptedKey); err != nil {
		t.Fatalf("query mailbox key: %v", err)
	}
	plaintext, err := compatDecryptString(encryptedKey, compatIntegrationSecretAAD(auth.OrganizationID, "GOOGLE_WORKSPACE", "example.com", "gmail_scan_private_key"))
	if err != nil {
		t.Fatalf("decrypt mailbox key with canonical AAD: %v", err)
	}
	if plaintext != privateKey {
		t.Fatalf("decrypted mailbox key mismatch")
	}
	if _, err := compatDecryptString(encryptedKey, auth.OrganizationID+":"+integrationID+":google_mailbox_private_key"); err == nil {
		t.Fatal("expected legacy ad-hoc AAD to fail")
	}

	legacyEncryptedKey, err := compatEncryptString(privateKey, compatLegacyIntegrationSecretAAD(auth.OrganizationID, integrationID, "google_mailbox_private_key"))
	if err != nil {
		t.Fatalf("encrypt legacy mailbox key: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE integration_connections SET encrypted_google_mailbox_scan_private_key = $1 WHERE id = $2`, legacyEncryptedKey, integrationID); err != nil {
		t.Fatalf("seed legacy mailbox key: %v", err)
	}
	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": clientEmail,
	}, auditAuth); err != nil {
		t.Fatalf("reuse legacy mailbox key: %v", err)
	}

	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": clientEmail,
	}, auditAuth); err != nil {
		t.Fatalf("reuse existing mailbox key: %v", err)
	}
	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": "other-scanner@example.com",
	}, auditAuth); err == nil {
		t.Fatal("expected changing client email without a new key to fail")
	}

	disabled := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{"enabled": false}, auditAuth)
	}))
	if disabled["enabled"] != false || disabled["serviceAccountClientEmail"] != nil {
		t.Fatalf("unexpected disabled config: %v", disabled)
	}

	var auditRows int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action IN ('integration.google_mailbox_scan.enable','integration.google_mailbox_scan.disable')`, auth.OrganizationID, integrationID).Scan(&auditRows); err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	if auditRows != 4 {
		t.Fatalf("expected 4 mailbox audit rows, got %d", auditRows)
	}
}

func TestDBSecurityOverview(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Prod",
		"externalAccountId": "T999000",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "xoxb-overview-token-123456"},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	assetID := compatID("ast")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_assets (id, organization_id, integration_id, type, name, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, created_at, updated_at) VALUES ($1,$2,$3,'DATA_RESOURCE',$4,ARRAY[]::text[],'HIGH','PUBLIC','UNASSIGNED',true,true,70,NOW(),NOW())`, assetID, auth.OrganizationID, integrationID, "Customer DB"); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	identityID := compatID("idn")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO saas_identities (id, organization_id, integration_id, provider, external_id, display_name, kind, status, linked_asset_ids, is_privileged, is_external, mfa_enabled, risk_score, created_at, updated_at) VALUES ($1,$2,$3,'SLACK',$4,$5,'USER','ACTIVE',$6,true,false,false,0,NOW(),NOW())`, identityID, auth.OrganizationID, integrationID, "admin@example.com", "Admin User", []string{assetID}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	overview, err := app.compatSecurityOverview(ctx, auth)
	if err != nil {
		t.Fatalf("security overview: %v", err)
	}
	data := dataMap(t, overview)
	identities, ok := data["identities"].([]any)
	if !ok || len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %v", data["identities"])
	}
	identity := identities[0].(map[string]any)
	if count := identity["linkedAssetCount"].(int); count < 1 {
		t.Fatalf("expected linkedAssetCount >= 1, got %d", count)
	}
	summary := data["summary"].(map[string]any)
	if summary["privilegedIdentities"].(int) != 1 {
		t.Fatalf("expected 1 privileged identity, got %v", summary["privilegedIdentities"])
	}
}

func mustCall(t *testing.T, fn func() (any, error)) any {
	t.Helper()
	result, err := fn()
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	return result
}
