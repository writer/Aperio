package bootstrap

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
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

func seedOrgUserWithPassword(t *testing.T, app *App, orgID, roleName, email, password string) compatAuth {
	t.Helper()
	ctx := context.Background()
	roleID, err := app.ensureCompatRole(ctx, orgID, roleName)
	if err != nil {
		t.Fatalf("seed %s role: %v", roleName, err)
	}
	userID := compatID("usr")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO users (id, organization_id, role_id, email, password_hash, display_name, is_active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,TRUE,NOW(),NOW())`, userID, orgID, roleID, email, compatHashPassword(password), roleName+" User"); err != nil {
		t.Fatalf("seed password user: %v", err)
	}
	return compatAuth{OrganizationID: orgID, UserID: userID, Email: email, Role: roleName}
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
	t.Run("typed test siem", func(t *testing.T) {
		req := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: victimSiemID})
		copyCompatHeaders(req.Header(), seedSessionHeader(t, app, attacker))
		_, err := app.TestSiemDestination(ctx, req)
		if code := connect.CodeOf(err); code != connect.CodeNotFound {
			t.Fatalf("typed TestSiemDestination: expected CodeNotFound, got %v (%v)", code, err)
		}
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
	t.Run("create security asset with foreign integration", func(t *testing.T) {
		out, err := app.compatCreateSecurityAsset(ctx, map[string]any{
			"integrationId":         victimIntegrationID,
			"type":                  "DATA_RESOURCE",
			"name":                  "Attacker Asset",
			"containsSensitiveData": true,
			"isPrivileged":          true,
			"riskScore":             90,
		}, attacker)
		assertNotFound(t, "compatCreateSecurityAsset", out, err)
	})
	t.Run("create security asset with foreign owner", func(t *testing.T) {
		out, err := app.compatCreateSecurityAsset(ctx, map[string]any{
			"ownerUserId":           victim.UserID,
			"type":                  "DATA_RESOURCE",
			"name":                  "Attacker Asset",
			"containsSensitiveData": true,
			"isPrivileged":          true,
			"riskScore":             90,
		}, attacker)
		assertNotFound(t, "compatCreateSecurityAsset owner", out, err)
	})
	t.Run("create risk exception with foreign asset", func(t *testing.T) {
		out, err := app.compatCreateRiskException(ctx, map[string]any{
			"assetId":              victimAssetID,
			"title":                "Attacker exception",
			"rationale":            "should not cross tenants",
			"compensatingControls": []any{},
		}, attacker)
		assertNotFound(t, "compatCreateRiskException asset", out, err)
	})
	t.Run("create risk exception with foreign finding", func(t *testing.T) {
		out, err := app.compatCreateRiskException(ctx, map[string]any{
			"findingId":            victimFindingID,
			"title":                "Attacker exception",
			"rationale":            "should not cross tenants",
			"compensatingControls": []any{},
		}, attacker)
		assertNotFound(t, "compatCreateRiskException finding", out, err)
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

func TestTenantIsolationSwitchWorkspaceRequiresTargetPassword(t *testing.T) {
	app, base := newTestDBApp(t)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	email := "same-email-" + randomBase36(10) + "@example.com"
	attacker := seedOrgUserWithPassword(t, app, base.OrganizationID, "OWNER", email, "attacker-password-123")
	victimUser := seedOrgUserWithPassword(t, app, victim.OrganizationID, "OWNER", email, "victim-password-123")
	auth, err := app.compatAuthFromSession(ctx, seedSessionHeader(t, app, attacker))
	if err != nil {
		t.Fatalf("seed attacker session auth: %v", err)
	}
	victimSlug := scanString(t, app, `SELECT slug FROM organizations WHERE id = $1`, victim.OrganizationID)

	_, err = app.compatSwitchWorkspace(ctx, map[string]any{
		"organizationSlug": victimSlug,
		"password":         "attacker-password-123",
	}, auth, http.Header{})
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		t.Fatalf("expected attacker password to be rejected for target workspace, got %v (%v)", code, err)
	}
	var victimSessions int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_sessions WHERE organization_id = $1 AND user_id = $2`, victim.OrganizationID, victimUser.UserID).Scan(&victimSessions); err != nil {
		t.Fatalf("count victim sessions after rejected switch: %v", err)
	}
	if victimSessions != 0 {
		t.Fatalf("rejected switch created %d victim session(s)", victimSessions)
	}

	out, err := app.compatSwitchWorkspace(ctx, map[string]any{
		"organizationSlug": victimSlug,
		"password":         "victim-password-123",
	}, auth, http.Header{})
	if err != nil {
		t.Fatalf("target password should allow workspace switch: %v", err)
	}
	switchedOrg := dataMap(t, out)["organization"].(compatSessionOrg)
	if switchedOrg.ID != victim.OrganizationID {
		t.Fatalf("switched organization = %s, want %s", switchedOrg.ID, victim.OrganizationID)
	}
}

func TestTypedSwitchWorkspaceHonorsRateLimit(t *testing.T) {
	app, base := newTestDBApp(t)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	email := "rate-limit-switch-" + randomBase36(10) + "@example.com"
	attacker := seedOrgUserWithPassword(t, app, base.OrganizationID, "OWNER", email, "attacker-password-123")
	seedOrgUserWithPassword(t, app, victim.OrganizationID, "OWNER", email, "victim-password-123")
	header := seedSessionHeader(t, app, attacker)
	path := "/api/v1/auth/workspaces/switch"
	seedExhaustedRateLimitBucket(t, app, header, http.MethodPost, path)

	req := connect.NewRequest(&aperiov1.SwitchWorkspaceRequest{
		OrganizationSlug: scanString(t, app, `SELECT slug FROM organizations WHERE id = $1`, victim.OrganizationID),
		Password:         "victim-password-123",
	})
	copyCompatHeaders(req.Header(), header)
	if _, err := app.SwitchWorkspace(ctx, req); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("expected rate-limited switch to return CodeResourceExhausted, got %v", err)
	}
}

func TestTenantIsolationRejectsPreviouslyMintedCrossTenantResetToken(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdMember := mustCall(t, func() (any, error) {
		return app.compatCreateMember(ctx, map[string]any{"email": "stale-reset-victim@example.com", "roleName": "ADMIN"}, victim)
	})
	victimUserID := createdMember.(map[string]any)["data"].(map[string]any)["id"].(string)

	token, tokenHash := compatToken()
	if _, err := app.db.ExecContext(ctx, `INSERT INTO auth_tokens (id, organization_id, user_id, created_by_user_id, purpose, token_hash, expires_at, created_at) VALUES ($1,$2,$3,$4,'PASSWORD_RESET',$5,NOW() + INTERVAL '1 hour',NOW())`, compatID("tok"), attacker.OrganizationID, victimUserID, attacker.UserID, tokenHash); err != nil {
		t.Fatalf("seed stale cross-tenant reset token: %v", err)
	}

	_, err := app.compatResetPassword(ctx, map[string]any{
		"token":    token,
		"password": "new-password-123",
	}, http.Header{})
	if err == nil {
		t.Fatal("expected stale cross-tenant reset token to be rejected")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
	}

	var sessions int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_sessions WHERE user_id = $1`, victimUserID).Scan(&sessions); err != nil {
		t.Fatalf("count victim sessions: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("stale cross-tenant reset token created %d victim session(s)", sessions)
	}
	var hashPresent bool
	if err := app.db.QueryRowContext(ctx, `SELECT password_hash IS NOT NULL FROM users WHERE id = $1`, victimUserID).Scan(&hashPresent); err != nil {
		t.Fatalf("query victim password hash: %v", err)
	}
	if hashPresent {
		t.Fatal("stale cross-tenant reset token updated the victim password")
	}
}

func TestAuthTokenConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	app, base := newTestDBApp(t)
	ctx := context.Background()
	user := seedOrgUserWithPassword(t, app, base.OrganizationID, "ADMIN", "reset-race-"+randomBase36(10)+"@example.com", "old-password-123")
	token, tokenHash := compatToken()
	if _, err := app.db.ExecContext(ctx, `INSERT INTO auth_tokens (id, organization_id, user_id, purpose, token_hash, expires_at, created_at) VALUES ($1,$2,$3,'PASSWORD_RESET',$4,NOW() + INTERVAL '1 hour',NOW())`, compatID("tok"), user.OrganizationID, user.UserID, tokenHash); err != nil {
		t.Fatalf("seed reset token: %v", err)
	}

	passwords := []string{
		"new-password-001",
		"new-password-002",
		"new-password-003",
		"new-password-004",
		"new-password-005",
		"new-password-006",
		"new-password-007",
		"new-password-008",
	}
	start := make(chan struct{})
	errs := make(chan error, len(passwords))
	for _, password := range passwords {
		password := password
		go func() {
			<-start
			_, err := app.compatResetPassword(ctx, map[string]any{"token": token, "password": password}, http.Header{})
			errs <- err
		}()
	}
	close(start)

	successes := 0
	for range passwords {
		err := <-errs
		if err == nil {
			successes++
			continue
		}
		if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
			t.Fatalf("expected losing token consumer to get CodeInvalidArgument, got %v (%v)", code, err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one token consumer to succeed, got %d", successes)
	}

	var consumed, sessions int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_tokens WHERE token_hash = $1 AND consumed_at IS NOT NULL`, tokenHash).Scan(&consumed); err != nil {
		t.Fatalf("count consumed token: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected token to be consumed once, got %d", consumed)
	}
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_sessions WHERE organization_id = $1 AND user_id = $2`, user.OrganizationID, user.UserID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions after concurrent reset: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("expected exactly one session after concurrent reset, got %d", sessions)
	}
}

func TestTenantIsolationRejectsPreviouslyMintedCrossTenantSession(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdMember := mustCall(t, func() (any, error) {
		return app.compatCreateMember(ctx, map[string]any{"email": "stale-session-victim@example.com", "roleName": "ADMIN"}, victim)
	})
	victimUserID := createdMember.(map[string]any)["data"].(map[string]any)["id"].(string)

	rawToken := randomURL(32)
	sessionID := compatID("ses")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO user_sessions (id, organization_id, user_id, token_hash, expires_at, last_seen_at, mfa_verified_at, created_at, updated_at) VALUES ($1,$2,$3,$4,NOW() + INTERVAL '1 hour',NOW(),NOW(),NOW(),NOW())`, sessionID, attacker.OrganizationID, victimUserID, hashOpaqueToken(rawToken)); err != nil {
		t.Fatalf("seed stale cross-tenant session: %v", err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+sessionID+"."+rawToken)

	if _, err := app.compatAuthFromSession(ctx, header); err == nil {
		t.Fatal("expected compat session auth to reject stale cross-tenant session")
	}
	if _, err := app.organizationIDFromSession(ctx, header); err == nil {
		t.Fatal("expected native session auth to reject stale cross-tenant session")
	}

	var lastSeen string
	if err := app.db.QueryRowContext(ctx, `SELECT last_seen_at::text FROM user_sessions WHERE id = $1`, sessionID).Scan(&lastSeen); err != nil {
		t.Fatalf("query stale session: %v", err)
	}
	var victimSessions int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND organization_id = $2`, victimUserID, victim.OrganizationID).Scan(&victimSessions); err != nil {
		t.Fatalf("count valid victim sessions: %v", err)
	}
	if victimSessions != 0 {
		t.Fatalf("expected no valid victim sessions, got %d", victimSessions)
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
