package bootstrap

import (
	"context"
	"testing"

	"connectrpc.com/connect"
)

// seedIsolationOrg provisions a second organization alongside the one created by
// newTestDBApp so the tests below can prove that one tenant's authenticated
// session can never read, mutate, or delete another tenant's resources. The org
// row is removed on cleanup; child rows cascade with it.
func seedIsolationOrg(t *testing.T, app *App) compatAuth {
	t.Helper()
	ctx := context.Background()
	orgID := compatID("org")
	slug := "iso-" + randomBase36(12)
	if _, err := app.db.ExecContext(ctx, `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, orgID, "Isolation Org", slug); err != nil {
		t.Fatalf("seed isolation organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = app.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return seedOrgAdmin(t, app, orgID)
}

// seedOrgAdmin provisions a real ADMIN user row for an existing organization and
// returns a session for it. A real user (rather than a synthetic id) is required
// so token/audit inserts referencing created_by_user_id satisfy their foreign
// keys. It also keeps the cross-tenant reset-link probe faithful: with a real
// attacker user, the unscoped insert would otherwise succeed, so the test fails
// loudly unless the handler rejects the foreign user.
func seedOrgAdmin(t *testing.T, app *App, orgID string) compatAuth {
	t.Helper()
	ctx := context.Background()
	roleID, err := app.ensureCompatRole(ctx, orgID, "OWNER")
	if err != nil {
		t.Fatalf("seed role: %v", err)
	}
	adminID := compatID("usr")
	email := "admin-" + randomBase36(10) + "@example.com"
	if _, err := app.db.ExecContext(ctx, `INSERT INTO users (id, organization_id, role_id, email, display_name, is_active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,TRUE,NOW(),NOW())`, adminID, orgID, roleID, email, "Org Admin"); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	return compatAuth{OrganizationID: orgID, UserID: adminID, Email: email, Role: "ADMIN"}
}

func assertNotFound(t *testing.T, label string, _ any, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a cross-tenant request to be rejected, got success", label)
	}
	if code := connect.CodeOf(err); code != connect.CodeNotFound {
		t.Fatalf("%s: expected CodeNotFound, got %v (%v)", label, code, err)
	}
}

// TestTenantIsolationByIDRoutesRejectForeignResources verifies that every
// by-id compatibility handler that resolves a resource refuses to operate on a
// resource owned by another organization. Resources are created in tenant B and
// then probed with tenant A's session.
func TestTenantIsolationByIDRoutesRejectForeignResources(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdIntegration := mustCall(t, func() (any, error) {
		return app.compatCreateIntegration(ctx, map[string]any{
			"provider":          "GOOGLE_WORKSPACE",
			"displayName":       "Victim Google",
			"externalAccountId": "victim.example.com",
			"mode":              "READ_ONLY",
			"credentials":       map[string]any{"accessToken": "victim-access-token"},
		}, victim)
	})
	victimIntegrationID := dataMap(t, createdIntegration)["id"].(string)

	createdSiem := mustCall(t, func() (any, error) {
		return app.compatCreateSiem(ctx, map[string]any{
			"kind":        "SPLUNK_HEC",
			"name":        "Victim Splunk",
			"endpointUrl": "https://8.8.8.8/services/collector",
			"streams":     []any{"FINDINGS"},
			"token":       "victim-splunk-token",
		}, victim)
	})
	victimSiemID := dataMap(t, createdSiem)["id"].(string)

	victimFindingID := compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],'{}'::jsonb,NOW())`, victimFindingID, victim.OrganizationID, victimIntegrationID, "dk-"+victimFindingID, "Victim finding", "seeded for isolation test"); err != nil {
		t.Fatalf("seed victim finding: %v", err)
	}

	victimAssetID := compatID("ast")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_assets (id, organization_id, type, name, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, created_at, updated_at) VALUES ($1,$2,'DATA_RESOURCE',$3,ARRAY[]::text[],'HIGH','PUBLIC','UNASSIGNED',true,true,70,NOW(),NOW())`, victimAssetID, victim.OrganizationID, "Victim Asset"); err != nil {
		t.Fatalf("seed victim asset: %v", err)
	}

	victimExceptionID := compatID("rex")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO risk_exceptions (id, organization_id, title, rationale, compensating_controls, status, created_at, updated_at) VALUES ($1,$2,$3,$4,ARRAY[]::text[],'ACTIVE',NOW(),NOW())`, victimExceptionID, victim.OrganizationID, "Victim Exception", "seeded for isolation test"); err != nil {
		t.Fatalf("seed victim exception: %v", err)
	}

	t.Run("integration checks", func(t *testing.T) {
		out, err := app.compatIntegrationChecks(ctx, victimIntegrationID, attacker)
		assertNotFound(t, "compatIntegrationChecks", out, err)
	})
	t.Run("update integration checks", func(t *testing.T) {
		out, err := app.compatUpdateIntegrationChecks(ctx, victimIntegrationID, map[string]any{"disabledChecks": []any{}}, attacker)
		assertNotFound(t, "compatUpdateIntegrationChecks", out, err)
	})
	t.Run("google mailbox config", func(t *testing.T) {
		out, err := app.compatGoogleMailboxConfig(ctx, victimIntegrationID, attacker)
		assertNotFound(t, "compatGoogleMailboxConfig", out, err)
	})
	t.Run("update google mailbox config", func(t *testing.T) {
		out, err := app.compatUpdateGoogleMailboxConfig(ctx, victimIntegrationID, map[string]any{"enabled": false}, attacker)
		assertNotFound(t, "compatUpdateGoogleMailboxConfig", out, err)
	})
	t.Run("force sync", func(t *testing.T) {
		out, err := app.compatForceSync(ctx, victimIntegrationID, attacker)
		assertNotFound(t, "compatForceSync", out, err)
	})
	t.Run("test siem", func(t *testing.T) {
		out, err := app.compatTestSiem(ctx, victimSiemID, attacker)
		assertNotFound(t, "compatTestSiem", out, err)
	})
	t.Run("remediate finding", func(t *testing.T) {
		out, err := app.compatRemediateFinding(ctx, victimFindingID, map[string]any{"action": "google.suspend_user"}, attacker)
		assertNotFound(t, "compatRemediateFinding", out, err)
	})
	t.Run("update security asset", func(t *testing.T) {
		out, err := app.compatUpdateSecurityAsset(ctx, victimAssetID, map[string]any{"name": "pwned"}, attacker)
		assertNotFound(t, "compatUpdateSecurityAsset", out, err)
	})
	t.Run("update risk exception", func(t *testing.T) {
		out, err := app.compatUpdateRiskException(ctx, victimExceptionID, map[string]any{"status": "REVOKED"}, attacker)
		assertNotFound(t, "compatUpdateRiskException", out, err)
	})

	// The probes above must not have leaked the resources into the attacker's
	// tenant or mutated the victim's rows.
	assertRowInOrg(t, app, "integration_connections", victimIntegrationID, victim.OrganizationID)
	assertRowInOrg(t, app, "siem_destinations", victimSiemID, victim.OrganizationID)
	assertRowInOrg(t, app, "security_assets", victimAssetID, victim.OrganizationID)
	if name := scanString(t, app, `SELECT name FROM security_assets WHERE id = $1`, victimAssetID); name != "Victim Asset" {
		t.Fatalf("victim asset name mutated cross-tenant: %q", name)
	}
	if status := scanString(t, app, `SELECT status::text FROM risk_exceptions WHERE id = $1`, victimExceptionID); status != "ACTIVE" {
		t.Fatalf("victim risk exception mutated cross-tenant: %q", status)
	}
}

// TestTenantIsolationSilentMutationsDoNotCrossTenants covers the handlers that
// intentionally return success even when no row matches (delete + status
// updates). They must be no-ops against another tenant's data rather than
// leaking or mutating it.
func TestTenantIsolationSilentMutationsDoNotCrossTenants(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdIntegration := mustCall(t, func() (any, error) {
		return app.compatCreateIntegration(ctx, map[string]any{
			"provider":          "SLACK",
			"displayName":       "Victim Slack",
			"externalAccountId": "TVICTIM",
			"mode":              "READ_ONLY",
			"credentials":       map[string]any{"accessToken": "victim-slack-token"},
		}, victim)
	})
	victimIntegrationID := dataMap(t, createdIntegration)["id"].(string)

	createdSiem := mustCall(t, func() (any, error) {
		return app.compatCreateSiem(ctx, map[string]any{
			"kind":        "PANTHER",
			"name":        "Victim Panther",
			"endpointUrl": "https://8.8.4.4/http",
			"streams":     []any{"FINDINGS"},
			"token":       "victim-panther-token",
		}, victim)
	})
	victimSiemID := dataMap(t, createdSiem)["id"].(string)

	victimFindingID := compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],'{}'::jsonb,NOW())`, victimFindingID, victim.OrganizationID, victimIntegrationID, "dk-"+victimFindingID, "Victim finding", "seeded for isolation test"); err != nil {
		t.Fatalf("seed victim finding: %v", err)
	}

	createdMember := mustCall(t, func() (any, error) {
		return app.compatCreateMember(ctx, map[string]any{"email": "victim-user@example.com", "roleName": "VIEWER"}, victim)
	})
	victimUserID := createdMember.(map[string]any)["data"].(map[string]any)["id"].(string)

	if _, err := app.compatDeleteIntegration(ctx, victimIntegrationID, attacker); err != nil {
		t.Fatalf("compatDeleteIntegration cross-tenant returned error: %v", err)
	}
	if _, err := app.compatDeleteSiem(ctx, victimSiemID, attacker); err != nil {
		t.Fatalf("compatDeleteSiem cross-tenant returned error: %v", err)
	}
	if _, err := app.compatUpdateFinding(ctx, victimFindingID, map[string]any{"status": "RESOLVED"}, attacker); err != nil {
		t.Fatalf("compatUpdateFinding cross-tenant returned error: %v", err)
	}
	if _, err := app.compatUpdateMemberRole(ctx, victimUserID, map[string]any{"roleName": "OWNER"}, attacker); err != nil {
		t.Fatalf("compatUpdateMemberRole cross-tenant returned error: %v", err)
	}

	assertRowInOrg(t, app, "integration_connections", victimIntegrationID, victim.OrganizationID)
	assertRowInOrg(t, app, "siem_destinations", victimSiemID, victim.OrganizationID)
	if status := scanString(t, app, `SELECT status::text FROM security_findings WHERE id = $1`, victimFindingID); status != "OPEN" {
		t.Fatalf("victim finding status mutated cross-tenant: %q", status)
	}
	role := scanString(t, app, `SELECT r.name::text FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, victimUserID)
	if role == "OWNER" {
		t.Fatalf("victim user role escalated cross-tenant to OWNER")
	}
}

// TestTenantIsolationMemberResetLinkRejectsForeignUser guards the
// admin/members/:id/reset-link route. Minting a password-reset token for a user
// in another organization would let an admin of one tenant take over an account
// in another (the reset consume path overwrites the password and disables MFA).
func TestTenantIsolationMemberResetLinkRejectsForeignUser(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdMember := mustCall(t, func() (any, error) {
		return app.compatCreateMember(ctx, map[string]any{"email": "reset-victim@example.com", "roleName": "ADMIN"}, victim)
	})
	victimUserID := createdMember.(map[string]any)["data"].(map[string]any)["id"].(string)

	out, err := app.compatCreateMemberReset(ctx, victimUserID, attacker)
	assertNotFound(t, "compatCreateMemberReset", out, err)

	var leaked int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_tokens WHERE user_id = $1 AND purpose = 'PASSWORD_RESET'`, victimUserID).Scan(&leaked); err != nil {
		t.Fatalf("count reset tokens: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("cross-tenant reset minted %d password-reset token(s) for a foreign user", leaked)
	}

	// The legitimate same-tenant reset must still succeed and mint exactly one token.
	if _, err := app.compatCreateMemberReset(ctx, victimUserID, victim); err != nil {
		t.Fatalf("same-tenant reset-link failed: %v", err)
	}
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_tokens WHERE user_id = $1 AND purpose = 'PASSWORD_RESET'`, victimUserID).Scan(&leaked); err != nil {
		t.Fatalf("count reset tokens after same-tenant reset: %v", err)
	}
	if leaked != 1 {
		t.Fatalf("same-tenant reset expected 1 token, got %d", leaked)
	}
}

func assertRowInOrg(t *testing.T, app *App, table, id, orgID string) {
	t.Helper()
	var gotOrg string
	err := app.db.QueryRowContext(context.Background(), `SELECT organization_id FROM `+table+` WHERE id = $1`, id).Scan(&gotOrg)
	if err != nil {
		t.Fatalf("%s row %s missing after cross-tenant probe: %v", table, id, err)
	}
	if gotOrg != orgID {
		t.Fatalf("%s row %s organization_id = %s, want %s", table, id, gotOrg, orgID)
	}
}

func scanString(t *testing.T, app *App, query, arg string) string {
	t.Helper()
	var value string
	if err := app.db.QueryRowContext(context.Background(), query, arg).Scan(&value); err != nil {
		t.Fatalf("scan %q: %v", query, err)
	}
	return value
}
