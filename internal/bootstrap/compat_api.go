package bootstrap

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"golang.org/x/crypto/scrypt"
)

const (
	compatEncryptionAlgorithm  = "aes-256-gcm"
	compatEncryptionKeyBytes   = 32
	compatEncryptionNonceBytes = 12
)

type compatEncryptedEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	IV         string `json:"iv"`
	Tag        string `json:"tag"`
	Ciphertext string `json:"ciphertext"`
}

type compatAuth struct {
	SessionID      string
	OrganizationID string
	UserID         string
	Email          string
	Role           string
}

type compatSessionUser struct {
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	DisplayName *string `json:"displayName"`
	MFAEnabled  bool    `json:"mfaEnabled"`
	Role        string  `json:"role"`
}

type compatSessionOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// normalizeCompatRoute turns a tunneled REST path into a low-cardinality route
// template by collapsing opaque identifiers (cuids, UUIDs, and seed-style
// prefixed IDs) into ":id". This keeps the wide event's http.tunnel.route
// dimension bounded so observability tooling groups by route, not by resource.
func normalizeCompatRoute(path string) string {
	trimmed := strings.TrimSpace(path)
	if index := strings.IndexAny(trimmed, "?#"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if trimmed == "" {
		return "unknown"
	}
	prefix := ""
	if strings.HasPrefix(trimmed, "/") {
		prefix = "/"
	}
	segments := strings.Split(strings.Trim(trimmed, "/"), "/")
	for index, segment := range segments {
		if looksLikeCompatID(segment) {
			segments[index] = ":id"
		}
	}
	return prefix + strings.Join(segments, "/")
}

// compatRouteTemplates is the closed set of normalized routes the compat tunnel
// actually dispatches (see handleCompatAPI). It bounds the cardinality of the
// http.tunnel.route telemetry dimension: anything not in this set is reported as
// "unmatched" so unauthenticated callers cannot inject arbitrary route strings.
// New routes added to the dispatcher should be added here too; until then they
// degrade safely to "unmatched" rather than leaking unbounded values.
var compatRouteTemplates = map[string]struct{}{
	"/api/v1/auth/signup":                               {},
	"/api/v1/auth/login":                                {},
	"/api/v1/auth/me":                                   {},
	"/api/v1/auth/logout":                               {},
	"/api/v1/auth/workspaces":                           {},
	"/api/v1/auth/workspaces/switch":                    {},
	"/api/v1/auth/forgot-password":                      {},
	"/api/v1/auth/reset-password":                       {},
	"/api/v1/auth/invitations/accept":                   {},
	"/api/v1/auth/mfa/setup":                            {},
	"/api/v1/auth/mfa/enable":                           {},
	"/api/v1/auth/mfa/disable":                          {},
	"/api/v1/findings/:id":                              {},
	"/api/v1/findings/:id/remediate":                    {},
	"/api/v1/integrations":                              {},
	"/api/v1/integrations/catalog":                      {},
	"/api/v1/integrations/:id":                          {},
	"/api/v1/integrations/:id/checks":                   {},
	"/api/v1/integrations/google-workspace/oauth/start": {},
	"/api/v1/integrations/:id/google-mailbox-scan":      {},
	"/api/v1/integrations/:id/force-sync":               {},
	"/api/v1/siem":                                      {},
	"/api/v1/siem/catalog":                              {},
	"/api/v1/siem/:id":                                  {},
	"/api/v1/siem/:id/test":                             {},
	"/api/v1/admin/settings":                            {},
	"/api/v1/admin/members":                             {},
	"/api/v1/admin/members/:id/reset-link":              {},
	"/api/v1/admin/members/:id/role":                    {},
	"/api/v1/admin/audit-logs":                          {},
	"/api/v1/security/overview":                         {},
	"/api/v1/security/assets":                           {},
	"/api/v1/security/assets/:id":                       {},
	"/api/v1/security/exceptions":                       {},
	"/api/v1/security/exceptions/:id":                   {},
}

// compatRouteLabel returns the bounded http.tunnel.route value for a tunneled
// path: a known normalized template, or "unmatched" for anything else.
func compatRouteLabel(path string) string {
	template := normalizeCompatRoute(path)
	if _, ok := compatRouteTemplates[template]; ok {
		return template
	}
	return "unmatched"
}

// compatMethodLabel returns the bounded http.tunnel.method value: a standard
// HTTP verb (matching how handleCompatAPI defaults a blank method to GET), or
// "other" for anything outside the known set.
func compatMethodLabel(raw string) string {
	method := strings.ToUpper(strings.TrimSpace(raw))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "other"
	}
}

// looksLikeCompatID reports whether a path segment is an opaque identifier
// rather than a static route component.
func looksLikeCompatID(segment string) bool {
	if isCompatUUID(segment) {
		return true
	}
	if len(segment) >= 20 && isCompatAlphanumeric(segment) {
		return true
	}
	if underscore := strings.IndexByte(segment, '_'); underscore > 0 && underscore < len(segment)-1 {
		prefix := segment[:underscore]
		body := segment[underscore+1:]
		if len(prefix) <= 12 && isCompatLowerAlpha(prefix) && len(body) >= 4 && isCompatIDBody(body) {
			return true
		}
	}
	return false
}

func isCompatAlphanumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func isCompatLowerAlpha(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func isCompatIDBody(value string) bool {
	if value == "" {
		return false
	}
	// compatID suffixes are base64.RawURLEncoding tokens, whose alphabet is
	// [A-Za-z0-9-_]; "-" must be accepted or ~1/3 of generated IDs would escape
	// normalization and leak into the route dimension.
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func isCompatUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		switch index {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func (a *App) handleCompatAPI(
	ctx context.Context,
	req *connect.Request[aperiov1.CallApiRequest],
) (string, http.Header, error) {
	// The web UI still speaks JSON-over-Connect for legacy REST-shaped routes.
	// This adapter validates the envelope, applies shared controls, and returns
	// the JSON body/header pair expected by the generated Connect method.
	if a.db == nil {
		return "", nil, connect.NewError(connect.CodeUnavailable, errors.New("database not configured"))
	}
	method := strings.ToUpper(strings.TrimSpace(req.Msg.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := strings.TrimSpace(req.Msg.Path)
	body := map[string]any{}
	if strings.TrimSpace(req.Msg.BodyJson) != "" {
		if err := json.Unmarshal([]byte(req.Msg.BodyJson), &body); err != nil {
			return "", nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid request body"))
		}
	}
	if err := a.compatRateLimit(ctx, req.Header(), method, path, body); err != nil {
		return "", nil, err
	}
	headers := http.Header{}
	segments := strings.Split(strings.Trim(path, "/"), "/")

	public := isPublicCompatPath(path)
	var auth compatAuth
	if !public {
		// Public auth bootstrap routes are rate limited but intentionally unauthenticated;
		// every other compatibility route resolves a tenant-scoped session first.
		var err error
		auth, err = a.compatAuthFromSession(ctx, req.Header())
		if err != nil {
			return "", nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
		}
	}

	result, err := a.dispatchCompatAPI(ctx, method, path, segments, body, auth, headers)
	if err != nil {
		return "", nil, err
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", nil, connect.NewError(connect.CodeInternal, errors.New("response serialization failed"))
	}
	return string(out), headers, nil
}

func (a *App) dispatchCompatAPI(
	ctx context.Context,
	method string,
	path string,
	segments []string,
	body map[string]any,
	auth compatAuth,
	headers http.Header,
) (any, error) {
	// Keep dispatch explicit rather than route-table driven so method, path shape,
	// auth, and role requirements remain visible next to the handler call.
	switch {
	case method == http.MethodPost && path == "/api/v1/auth/signup":
		return a.compatSignup(ctx, body, headers)
	case method == http.MethodPost && path == "/api/v1/auth/login":
		return a.compatLogin(ctx, body, headers)
	case method == http.MethodGet && path == "/api/v1/auth/me":
		return a.compatSession(ctx, auth, "")
	case method == http.MethodPost && path == "/api/v1/auth/logout":
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, auth.SessionID)
		headers.Add("Set-Cookie", expiredCompatSessionCookie())
		return map[string]any{"data": map[string]bool{"ok": true}}, nil
	case method == http.MethodGet && path == "/api/v1/auth/workspaces":
		return a.compatWorkspaces(ctx, auth)
	case method == http.MethodPost && path == "/api/v1/auth/workspaces/switch":
		return a.compatSwitchWorkspace(ctx, body, auth, headers)
	case method == http.MethodPost && path == "/api/v1/auth/forgot-password":
		return a.compatForgotPassword(ctx, body)
	case method == http.MethodPost && path == "/api/v1/auth/reset-password":
		return a.compatResetPassword(ctx, body, headers)
	case method == http.MethodPost && path == "/api/v1/auth/invitations/accept":
		return a.compatAcceptInvite(ctx, body, headers)
	case method == http.MethodPost && path == "/api/v1/auth/mfa/setup":
		return a.compatMFASetup(ctx, auth)
	case method == http.MethodPost && path == "/api/v1/auth/mfa/enable":
		return a.compatMFAEnable(ctx, body, auth)
	case method == http.MethodPost && path == "/api/v1/auth/mfa/disable":
		return a.compatMFADisable(ctx, body, auth)
	case method == http.MethodPatch && len(segments) == 4 && segments[0] == "api" && segments[2] == "findings":
		return a.compatUpdateFinding(ctx, segments[3], body, auth)
	case method == http.MethodGet && path == "/api/v1/integrations/catalog":
		return map[string]any{"data": compatConnectorCatalog()}, nil
	case method == http.MethodPost && path == "/api/v1/integrations":
		return a.compatCreateIntegration(ctx, body, auth)
	case method == http.MethodDelete && len(segments) == 4 && segments[2] == "integrations":
		return a.compatDeleteIntegration(ctx, segments[3], auth)
	case method == http.MethodGet && len(segments) == 5 && segments[2] == "integrations" && segments[4] == "checks":
		return a.compatIntegrationChecks(ctx, segments[3], auth)
	case method == http.MethodPatch && len(segments) == 5 && segments[2] == "integrations" && segments[4] == "checks":
		return a.compatUpdateIntegrationChecks(ctx, segments[3], body, auth)
	case method == http.MethodPost && path == "/api/v1/integrations/google-workspace/oauth/start":
		if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
			return nil, err
		}
		return a.compatGoogleOAuthStart(body, auth)
	case method == http.MethodGet && len(segments) == 5 && segments[2] == "integrations" && segments[4] == "google-mailbox-scan":
		return a.compatGoogleMailboxConfig(ctx, segments[3], auth)
	case method == http.MethodPatch && len(segments) == 5 && segments[2] == "integrations" && segments[4] == "google-mailbox-scan":
		return a.compatUpdateGoogleMailboxConfig(ctx, segments[3], body, auth)
	case method == http.MethodPost && len(segments) == 5 && segments[2] == "integrations" && segments[4] == "force-sync":
		return a.compatForceSync(ctx, segments[3], auth)
	case method == http.MethodGet && path == "/api/v1/siem/catalog":
		return map[string]any{"data": compatSiemCatalog()}, nil
	case method == http.MethodPost && path == "/api/v1/siem":
		return a.compatCreateSiem(ctx, body, auth)
	case method == http.MethodDelete && len(segments) == 4 && segments[2] == "siem":
		return a.compatDeleteSiem(ctx, segments[3], auth)
	case method == http.MethodPost && len(segments) == 5 && segments[2] == "siem" && segments[4] == "test":
		return a.compatTestSiem(ctx, segments[3], auth)
	case method == http.MethodPost && len(segments) == 5 && segments[2] == "findings" && segments[4] == "remediate":
		return a.compatRemediateFinding(ctx, segments[3], body, auth)
	case method == http.MethodGet && path == "/api/v1/admin/settings":
		return a.compatTenantSettings(ctx, auth)
	case method == http.MethodPatch && path == "/api/v1/admin/settings":
		return a.compatUpdateTenantSettings(ctx, body, auth)
	case method == http.MethodGet && path == "/api/v1/admin/members":
		return a.compatMembers(ctx, auth)
	case method == http.MethodPost && path == "/api/v1/admin/members":
		return a.compatCreateMember(ctx, body, auth)
	case method == http.MethodPost && len(segments) == 6 && segments[2] == "admin" && segments[3] == "members" && segments[5] == "reset-link":
		return a.compatCreateMemberReset(ctx, segments[4], auth)
	case method == http.MethodPatch && len(segments) == 6 && segments[2] == "admin" && segments[3] == "members" && segments[5] == "role":
		return a.compatUpdateMemberRole(ctx, segments[4], body, auth)
	case method == http.MethodGet && path == "/api/v1/admin/audit-logs":
		return a.compatAuditLogs(ctx, auth)
	case method == http.MethodGet && path == "/api/v1/security/overview":
		return a.compatSecurityOverview(ctx, auth)
	case method == http.MethodPost && path == "/api/v1/security/assets":
		return a.compatCreateSecurityAsset(ctx, body, auth)
	case method == http.MethodPatch && len(segments) == 5 && segments[2] == "security" && segments[3] == "assets":
		return a.compatUpdateSecurityAsset(ctx, segments[4], body, auth)
	case method == http.MethodPost && path == "/api/v1/security/exceptions":
		return a.compatCreateRiskException(ctx, body, auth)
	case method == http.MethodPatch && len(segments) == 5 && segments[2] == "security" && segments[3] == "exceptions":
		return a.compatUpdateRiskException(ctx, segments[4], body, auth)
	default:
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("unknown Go API route %s %s", method, path))
	}
}

func isPublicCompatPath(path string) bool {
	// Only account bootstrap endpoints bypass session auth. Token-bearing reset
	// and invitation flows do their own one-time-token validation downstream.
	switch path {
	case "/api/v1/auth/signup",
		"/api/v1/auth/login",
		"/api/v1/auth/forgot-password",
		"/api/v1/auth/reset-password",
		"/api/v1/auth/invitations/accept":
		return true
	default:
		return false
	}
}

func (a *App) compatRateLimit(
	ctx context.Context,
	header http.Header,
	method string,
	path string,
	body map[string]any,
) error {
	if method != http.MethodPost {
		return nil
	}
	max, window, ok := compatRateLimitPolicy(path)
	if !ok {
		return nil
	}
	client := compatClientIdentity(header)
	// Rate limit by both network identity and the submitted subject. This slows
	// distributed guessing against a single email/token while still bounding one
	// noisy client that rotates submitted subjects.
	subject := compatRateLimitSubject([]string{
		requiredString(body, "organizationSlug"),
		requiredString(body, "workspaceSlug"),
		requiredString(body, "ownerEmail"),
		requiredString(body, "email"),
		requiredString(body, "token"),
	})
	now := time.Now()
	ipKey := compatRateLimitKey(method, path, client, "")
	if err := a.compatConsumeRateLimit(ctx, ipKey, max, window, now); err != nil {
		return err
	}
	if subject != "" {
		subjectKey := compatRateLimitKey(method, path, client, subject)
		if err := a.compatConsumeRateLimit(ctx, subjectKey, max, window, now); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) compatConsumeRateLimit(ctx context.Context, key string, max int, window time.Duration, now time.Time) error {
	resetAt := now.Add(window)
	var count int
	// The bucket update is a single UPSERT so concurrent login/reset attempts see
	// a consistent counter without application-level locks.
	err := a.db.QueryRowContext(ctx, `
		INSERT INTO rate_limit_buckets (key, count, reset_at, created_at, updated_at)
		VALUES ($1, 1, $2, NOW(), NOW())
		ON CONFLICT (key) DO UPDATE SET
		  count = CASE
		    WHEN rate_limit_buckets.reset_at <= $3 THEN 1
		    ELSE rate_limit_buckets.count + 1
		  END,
		  reset_at = CASE
		    WHEN rate_limit_buckets.reset_at <= $3 THEN EXCLUDED.reset_at
		    ELSE rate_limit_buckets.reset_at
		  END,
		  updated_at = NOW()
		RETURNING count
	`, key, resetAt, now).Scan(&count)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("rate limiter unavailable"))
	}
	if count > max {
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many requests"))
	}
	return nil
}

func compatRateLimitKey(method, path, client, subject string) string {
	scope := "ip"
	if subject != "" {
		scope = "subject"
	}
	return hashOpaqueToken(strings.Join([]string{"compat-rate-limit", scope, method, path, client, subject}, ":"))
}

func compatRateLimitSubject(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ":")
}

func compatRateLimitPolicy(path string) (int, time.Duration, bool) {
	switch path {
	case "/api/v1/auth/signup":
		return 5, time.Hour, true
	case "/api/v1/auth/login":
		return 15, 10 * time.Minute, true
	case "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password", "/api/v1/auth/invitations/accept":
		return 10, 15 * time.Minute, true
	default:
		if strings.HasPrefix(path, "/api/v1/integrations/") && strings.HasSuffix(path, "/force-sync") {
			return 10, 10 * time.Minute, true
		}
		if strings.HasPrefix(path, "/api/v1/findings/") && strings.HasSuffix(path, "/remediate") {
			return 20, 10 * time.Minute, true
		}
		return 0, 0, false
	}
}

func compatClientIdentity(header http.Header) string {
	// Prefer the right-most forwarded IP, which is normally the closest trusted
	// proxy hop in deployments that append X-Forwarded-For.
	forwarded := strings.Split(header.Get("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		if client := strings.TrimSpace(forwarded[index]); client != "" {
			return client
		}
	}
	if client := strings.TrimSpace(header.Get("X-Real-IP")); client != "" {
		return client
	}
	return "unknown"
}

func (a *App) compatAuthFromSession(ctx context.Context, header http.Header) (compatAuth, error) {
	token := sessionToken(header)
	if token == "" {
		return compatAuth{}, errors.New("missing session")
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return compatAuth{}, errors.New("invalid session")
	}
	var auth compatAuth
	var lastSeenAt time.Time
	// Sessions are stored as id plus token hash. MFA-enabled accounts require an
	// MFA-verified session row, preventing password-only sessions from reaching
	// protected compatibility APIs.
	err := a.db.QueryRowContext(ctx, `
		SELECT us.id, u.organization_id, u.id, u.email, r.name::text, us.last_seen_at
		FROM user_sessions us
		JOIN users u ON u.id = us.user_id AND u.organization_id = us.organization_id
		JOIN roles r ON r.id = u.role_id
		WHERE us.id = $1
		  AND us.token_hash = $2
		  AND us.revoked_at IS NULL
		  AND us.expires_at > NOW()
		  AND u.is_active = TRUE
		  AND (u.mfa_enabled = FALSE OR us.mfa_verified_at IS NOT NULL)
	`, parts[0], hashOpaqueToken(parts[1])).Scan(&auth.SessionID, &auth.OrganizationID, &auth.UserID, &auth.Email, &auth.Role, &lastSeenAt)
	if err != nil {
		return compatAuth{}, err
	}
	if time.Since(lastSeenAt) > time.Duration(a.cfg.SessionIdleMinutes)*time.Minute {
		// Idle timeout revokes the session server-side; the client receives only an
		// unauthenticated error and must re-establish a fresh session.
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, auth.SessionID)
		return compatAuth{}, errors.New("session idle timeout")
	}
	if time.Since(lastSeenAt) > time.Minute {
		// Throttle last_seen_at writes so active sessions do not update on every
		// UI polling request.
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_at = NOW() WHERE id = $1`, auth.SessionID)
	}
	return auth, nil
}

func (a *App) compatSignup(ctx context.Context, body map[string]any, headers http.Header) (any, error) {
	orgName := requiredString(body, "organizationName")
	orgSlug := requiredString(body, "organizationSlug")
	email := strings.ToLower(requiredString(body, "ownerEmail"))
	password := requiredString(body, "password")
	displayName := optionalStringPtr(body, "ownerDisplayName")
	if orgName == "" || orgSlug == "" || email == "" || len(password) < 12 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid signup payload"))
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer tx.Rollback()
	orgID, roleID, userID := compatID("org"), compatID("role"), compatID("usr")
	if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, name, slug, notification_email, created_at, updated_at) VALUES ($1,$2,$3,$4,NOW(),NOW())`, orgID, orgName, orgSlug, optionalStringPtr(body, "notificationEmail")); err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("workspace slug is already in use"))
	}
	for _, role := range []string{"OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"} {
		id := compatID("role")
		if role == "OWNER" {
			id = roleID
		}
		perms := "ARRAY['read']::text[]"
		if role == "OWNER" || role == "ADMIN" {
			perms = "ARRAY['*']::text[]"
		} else if role == "SECURITY_ANALYST" {
			perms = "ARRAY['read','triage','remediate']::text[]"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, organization_id, name, permissions, created_at, updated_at) VALUES ($1,$2,$3,`+perms+`,NOW(),NOW())`, id, orgID, role); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, organization_id, role_id, email, password_hash, display_name, mfa_enabled, is_active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,FALSE,TRUE,NOW(),NOW())`, userID, orgID, roleID, email, compatHashPassword(password), displayName); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	_, _ = tx.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, created_at) VALUES ($1,$2,$3,'auth.signup','organization',$2,NOW())`, compatID("aud"), orgID, userID)
	session, err := compatIssueSessionTx(ctx, tx, orgID, userID, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	headers.Add("Set-Cookie", compatSessionCookie(session))
	return map[string]any{"data": map[string]any{"token": session, "user": map[string]any{"id": userID, "email": email, "displayName": displayName, "mfaEnabled": false, "role": "OWNER"}, "organization": map[string]any{"id": orgID, "name": orgName, "slug": orgSlug}}}, nil
}

func (a *App) compatLogin(ctx context.Context, body map[string]any, headers http.Header) (any, error) {
	slug, email, password := requiredString(body, "organizationSlug"), strings.ToLower(requiredString(body, "email")), requiredString(body, "password")
	var userID, orgID, orgName, orgSlug, role, hash string
	var displayName sql.NullString
	var mfaSecret sql.NullString
	var mfaLastCounter sql.NullInt64
	var mfaEnabled bool
	err := a.db.QueryRowContext(ctx, `
		SELECT u.id, o.id, o.name, o.slug, r.name::text, u.password_hash, u.display_name, u.mfa_enabled, u.mfa_secret_encrypted, u.mfa_last_counter
		FROM users u JOIN organizations o ON o.id = u.organization_id JOIN roles r ON r.id = u.role_id
		WHERE o.slug = $1 AND u.email = $2 AND u.is_active = TRUE
	`, slug, email).Scan(&userID, &orgID, &orgName, &orgSlug, &role, &hash, &displayName, &mfaEnabled, &mfaSecret, &mfaLastCounter)
	if err != nil || !compatVerifyPassword(password, hash) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	}
	mfaCounter := int64(0)
	if mfaEnabled {
		if !mfaSecret.Valid {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("mfa cannot be verified"))
		}
		counter, ok := compatVerifyTOTPWithCounter(mfaSecret.String, requiredString(body, "totpCode"), mfaLastCounter)
		if !ok {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid authentication code"))
		}
		mfaCounter = counter
	}
	tx, _ := a.db.BeginTx(ctx, nil)
	defer tx.Rollback()
	if mfaEnabled {
		_, _ = tx.ExecContext(ctx, `UPDATE users SET last_login_at = NOW(), mfa_last_counter = $2, updated_at = NOW() WHERE id = $1`, userID, mfaCounter)
	} else {
		_, _ = tx.ExecContext(ctx, `UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`, userID)
	}
	session, err := compatIssueSessionTx(ctx, tx, orgID, userID, !mfaEnabled || requiredString(body, "totpCode") != "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	headers.Add("Set-Cookie", compatSessionCookie(session))
	return map[string]any{"data": compatSessionPayload(session, compatSessionUser{ID: userID, Email: email, DisplayName: nullStringPtr(displayName), MFAEnabled: mfaEnabled, Role: role}, compatSessionOrg{ID: orgID, Name: orgName, Slug: orgSlug})}, nil
}

func (a *App) compatSession(ctx context.Context, auth compatAuth, token string) (any, error) {
	var user compatSessionUser
	var org compatSessionOrg
	var displayName sql.NullString
	if err := a.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.display_name, u.mfa_enabled, r.name::text, o.id, o.name, o.slug
		FROM users u JOIN roles r ON r.id = u.role_id JOIN organizations o ON o.id = u.organization_id
		WHERE u.id = $1 AND u.organization_id = $2
	`, auth.UserID, auth.OrganizationID).Scan(&user.ID, &user.Email, &displayName, &user.MFAEnabled, &user.Role, &org.ID, &org.Name, &org.Slug); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	user.DisplayName = nullStringPtr(displayName)
	return map[string]any{"data": compatSessionPayload(token, user, org)}, nil
}

func (a *App) compatWorkspaces(ctx context.Context, auth compatAuth) (any, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT o.id, o.name, o.slug, r.name::text, o.id = $2
		FROM users u JOIN organizations o ON o.id = u.organization_id JOIN roles r ON r.id = u.role_id
		WHERE u.email = $1 AND u.is_active = TRUE ORDER BY o.name ASC
	`, auth.Email, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	data := []map[string]any{}
	for rows.Next() {
		var id, name, slug, role string
		var current bool
		_ = rows.Scan(&id, &name, &slug, &role, &current)
		data = append(data, map[string]any{"id": id, "name": name, "slug": slug, "role": role, "current": current})
	}
	return map[string]any{"data": data}, nil
}

func (a *App) compatSwitchWorkspace(ctx context.Context, body map[string]any, auth compatAuth, headers http.Header) (any, error) {
	slug := requiredString(body, "organizationSlug")
	var target compatAuth
	var orgName string
	var targetMFAEnabled bool
	var targetMFASecret sql.NullString
	var targetMFALastCounter sql.NullInt64
	err := a.db.QueryRowContext(ctx, `
		SELECT us.id, o.id, u.id, u.email, r.name::text, o.name, u.mfa_enabled, u.mfa_secret_encrypted, u.mfa_last_counter
		FROM users u JOIN organizations o ON o.id = u.organization_id JOIN roles r ON r.id = u.role_id
		LEFT JOIN user_sessions us ON us.id = $3
		WHERE u.email = $1 AND o.slug = $2 AND u.is_active = TRUE
	`, auth.Email, slug, auth.SessionID).Scan(&target.SessionID, &target.OrganizationID, &target.UserID, &target.Email, &target.Role, &orgName, &targetMFAEnabled, &targetMFASecret, &targetMFALastCounter)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
	}
	targetMFACounter := int64(0)
	if targetMFAEnabled {
		if !targetMFASecret.Valid {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("target workspace mfa cannot be verified"))
		}
		counter, ok := compatVerifyTOTPWithCounter(targetMFASecret.String, requiredString(body, "totpCode"), targetMFALastCounter)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("target workspace mfa verification required"))
		}
		targetMFACounter = counter
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, auth.SessionID)
	tx, _ := a.db.BeginTx(ctx, nil)
	defer tx.Rollback()
	if targetMFAEnabled {
		_, _ = tx.ExecContext(ctx, `UPDATE users SET mfa_last_counter = $2, last_login_at = NOW(), updated_at = NOW() WHERE id = $1`, target.UserID, targetMFACounter)
	}
	session, err := compatIssueSessionTx(ctx, tx, target.OrganizationID, target.UserID, !targetMFAEnabled || targetMFACounter > 0)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	headers.Add("Set-Cookie", compatSessionCookie(session))
	return a.compatSession(ctx, compatAuth{OrganizationID: target.OrganizationID, UserID: target.UserID}, session)
}

func (a *App) compatForgotPassword(ctx context.Context, body map[string]any) (any, error) {
	slug, email := requiredString(body, "organizationSlug"), strings.ToLower(requiredString(body, "email"))
	var orgID, orgName, userID string
	err := a.db.QueryRowContext(ctx, `SELECT o.id, o.name, u.id FROM organizations o JOIN users u ON u.organization_id = o.id WHERE o.slug = $1 AND u.email = $2 AND u.is_active = TRUE`, slug, email).Scan(&orgID, &orgName, &userID)
	if err != nil {
		return map[string]any{"data": map[string]any{"accepted": true}}, nil
	}
	token, tokenHash := compatToken()
	expires := time.Now().Add(2 * time.Hour)
	_, _ = a.db.ExecContext(ctx, `UPDATE auth_tokens SET consumed_at = NOW() WHERE organization_id = $1 AND user_id = $2 AND purpose = 'PASSWORD_RESET' AND consumed_at IS NULL`, orgID, userID)
	_, _ = a.db.ExecContext(ctx, `INSERT INTO auth_tokens (id, organization_id, user_id, purpose, token_hash, expires_at, created_at) VALUES ($1,$2,$3,'PASSWORD_RESET',$4,$5,NOW())`, compatID("tok"), orgID, userID, tokenHash, expires)
	return map[string]any{"data": map[string]any{"accepted": true, "delivery": "manual_link", "resetUrl": compatAuthLink("/reset-password", token), "expiresAt": expires.UTC().Format(time.RFC3339Nano), "organizationName": orgName}}, nil
}

func (a *App) compatResetPassword(ctx context.Context, body map[string]any, headers http.Header) (any, error) {
	return a.compatConsumeAuthToken(ctx, requiredString(body, "token"), requiredString(body, "password"), "PASSWORD_RESET", headers)
}

func (a *App) compatAcceptInvite(ctx context.Context, body map[string]any, headers http.Header) (any, error) {
	return a.compatConsumeAuthToken(ctx, requiredString(body, "token"), requiredString(body, "password"), "INVITE", headers)
}

func (a *App) compatConsumeAuthToken(ctx context.Context, token, password, purpose string, headers http.Header) (any, error) {
	if len(password) < 12 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid password"))
	}
	var orgID, orgName, orgSlug, userID, email, role string
	var displayName sql.NullString
	err := a.db.QueryRowContext(ctx, `
		SELECT o.id, o.name, o.slug, u.id, u.email, u.display_name, r.name::text
		FROM auth_tokens at JOIN users u ON u.id = at.user_id AND u.organization_id = at.organization_id JOIN organizations o ON o.id = at.organization_id JOIN roles r ON r.id = u.role_id
		WHERE at.token_hash = $1 AND at.purpose = $2 AND at.consumed_at IS NULL AND at.expires_at > NOW()
	`, hashOpaqueToken(token), purpose).Scan(&orgID, &orgName, &orgSlug, &userID, &email, &displayName, &role)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid or expired token"))
	}
	tx, _ := a.db.BeginTx(ctx, nil)
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `UPDATE users SET password_hash = $1, is_active = TRUE, mfa_enabled = FALSE, mfa_secret_encrypted = NULL, mfa_last_counter = NULL, updated_at = NOW() WHERE id = $2 AND organization_id = $3`, compatHashPassword(password), userID, orgID)
	_, _ = tx.ExecContext(ctx, `UPDATE auth_tokens SET consumed_at = NOW() WHERE token_hash = $1`, hashOpaqueToken(token))
	_, _ = tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	session, err := compatIssueSessionTx(ctx, tx, orgID, userID, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	headers.Add("Set-Cookie", compatSessionCookie(session))
	return map[string]any{"data": compatSessionPayload(session, compatSessionUser{ID: userID, Email: email, DisplayName: nullStringPtr(displayName), MFAEnabled: false, Role: role}, compatSessionOrg{ID: orgID, Name: orgName, Slug: orgSlug})}, nil
}

func (a *App) compatMFASetup(ctx context.Context, auth compatAuth) (any, error) {
	secret := compatBase32(20)
	_, _ = a.db.ExecContext(ctx, `UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = FALSE, mfa_last_counter = NULL, updated_at = NOW() WHERE id = $2 AND organization_id = $3`, secret, auth.UserID, auth.OrganizationID)
	return map[string]any{"data": map[string]any{"secret": secret, "otpauthUrl": compatOtpAuthURL(auth.Email, secret)}}, nil
}

func (a *App) compatMFAEnable(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	var secret sql.NullString
	var lastCounter sql.NullInt64
	if err := a.db.QueryRowContext(ctx, `SELECT mfa_secret_encrypted, mfa_last_counter FROM users WHERE id = $1 AND organization_id = $2`, auth.UserID, auth.OrganizationID).Scan(&secret, &lastCounter); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("mfa setup is required"))
	}
	counter, ok := compatVerifyTOTPWithCounter(secret.String, requiredString(body, "code"), lastCounter)
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid authentication code"))
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = TRUE, mfa_last_counter = $3, updated_at = NOW() WHERE id = $1 AND organization_id = $2`, auth.UserID, auth.OrganizationID, counter)
	_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET mfa_verified_at = NOW() WHERE id = $1`, auth.SessionID)
	return a.compatSession(ctx, auth, "")
}

func (a *App) compatMFADisable(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	var hash string
	if err := a.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = $1 AND organization_id = $2`, auth.UserID, auth.OrganizationID).Scan(&hash); err != nil || !compatVerifyPassword(requiredString(body, "password"), hash) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid password"))
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = FALSE, mfa_secret_encrypted = NULL, mfa_last_counter = NULL, updated_at = NOW() WHERE id = $1`, auth.UserID)
	_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET mfa_verified_at = NULL WHERE id = $1`, auth.SessionID)
	return a.compatSession(ctx, auth, "")
}

// Remaining route handlers intentionally preserve the web contract while keeping
// provider-specific effects explicit and auditable in Go.
func (a *App) compatUpdateFinding(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	status := requiredString(body, "status")
	if status != "RESOLVED" && status != "MUTED" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid finding status"))
	}
	_, err := a.db.ExecContext(ctx, `UPDATE security_findings SET status = $1, resolved_at = NOW(), resolved_by_id = $2 WHERE id = $3 AND organization_id = $4`, status, auth.UserID, id, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	_, _ = a.db.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES ($1,$2,$3,$4,'security_finding',$5,$6,NOW())`, compatID("aud"), auth.OrganizationID, auth.UserID, "finding.status.update", id, json.RawMessage(`{}`))
	return map[string]any{"data": map[string]any{"id": id, "status": status}}, nil
}

func (a *App) compatCreateIntegration(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	id := compatID("int")
	provider, displayName, external := strings.ToUpper(requiredString(body, "provider")), requiredString(body, "displayName"), requiredString(body, "externalAccountId")
	connector := findConnectorDefinition(provider)
	if connector == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("unsupported connector"))
	}
	if connector.Availability != "production_ready" && os.Getenv("APERIO_ALLOW_PREVIEW_CONNECTORS") != "true" {
		message := connector.ReadinessNote
		if message == "" {
			message = connector.Name + " is still in preview and is not enabled for real customer data."
		}
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New(message))
	}
	if err := validateCompatExternalAccount(provider, external); err != nil {
		return nil, err
	}
	mode := strings.ToUpper(stringDefault(body, "mode", "READ_ONLY"))
	if mode != "READ_ONLY" && mode != "REMEDIATION" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid integration mode"))
	}
	accessToken := nestedString(body, "credentials", "accessToken")
	if len(accessToken) < 8 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("integration access token is required"))
	}
	var exists bool
	if err := a.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM integration_connections WHERE organization_id = $1 AND provider = $2 AND external_account_id = $3)`, auth.OrganizationID, provider, external).Scan(&exists); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if exists {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("connector already registered for this account"))
	}
	// Credential AAD includes the provider account identity so encrypted tokens
	// cannot be transplanted across organizations, providers, or external tenants.
	encryptedAccessToken, err := compatEncryptString(accessToken, compatIntegrationSecretAAD(auth.OrganizationID, provider, external, "access_token"))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("integration credential encryption failed"))
	}
	refreshToken, err := encryptedOptionalSecret(asMap(body["credentials"]), "refreshToken", compatIntegrationSecretAAD(auth.OrganizationID, provider, external, "refresh_token"))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("integration refresh token encryption failed"))
	}
	webhookSecret, err := encryptedOptionalSecret(asMap(body["credentials"]), "webhookSecret", compatIntegrationSecretAAD(auth.OrganizationID, provider, external, "webhook_secret"))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("integration webhook secret encryption failed"))
	}
	scopes := compatScopesForMode(provider, mode)
	disabledChecks := compatDefaultDisabledChecks(provider)
	// The compatibility path creates the integration and its application asset in
	// one request so the security overview can immediately reason about the new
	// control plane, even before the first ingestion job runs.
	if _, err := a.db.ExecContext(ctx, `INSERT INTO integration_connections (id, organization_id, provider, display_name, external_account_id, encrypted_access_token, encrypted_refresh_token, encrypted_webhook_secret, status, mode, scopes, disabled_checks, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'CONNECTED',$9,$10,$11,NOW(),NOW())`, id, auth.OrganizationID, provider, displayName, external, encryptedAccessToken, refreshToken, webhookSecret, mode, scopes, disabledChecks); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	isPrivileged := mode == "REMEDIATION"
	riskScore := 35
	if isPrivileged {
		riskScore = 55
	}
	_, _ = a.db.ExecContext(ctx, `INSERT INTO security_assets (id, organization_id, integration_id, type, provider, name, summary, external_id, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, created_at, updated_at) VALUES ($1,$2,$3,'APPLICATION',$4,$5,$6,$7,$8,'HIGH','INTERNAL','ASSIGNED',false,$9,$10,NOW(),NOW()) ON CONFLICT DO NOTHING`, compatID("ast"), auth.OrganizationID, id, provider, displayName, strings.ReplaceAll(provider, "_", " ")+" control plane", external, []string{"integration", strings.ToLower(mode)}, isPrivileged, riskScore)
	a.writeCompatAudit(ctx, auth, "integration.connect", "integration_connection", id, map[string]any{"provider": provider, "displayName": displayName, "externalAccountId": external, "mode": mode})
	return map[string]any{"data": map[string]any{"id": id, "provider": provider, "displayName": displayName, "externalAccountId": external, "status": "CONNECTED", "mode": mode, "scopes": scopes, "disabledChecks": disabledChecks, "googleMailboxScanEnabled": false, "googleMailboxScanClientEmail": nil, "lastSyncAt": nil, "createdAt": time.Now().UTC().Format(time.RFC3339Nano)}}, nil
}

func (a *App) compatDeleteIntegration(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(ctx, `DELETE FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return map[string]any{"data": map[string]bool{"ok": true}}, nil
}

func (a *App) compatIntegrationChecks(ctx context.Context, id string, auth compatAuth) (any, error) {
	var provider string
	var disabledJSON string
	if err := a.db.QueryRowContext(ctx, `SELECT provider::text, array_to_json(disabled_checks)::text FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID).Scan(&provider, &disabledJSON); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
	}
	disabled := []string{}
	_ = json.Unmarshal([]byte(disabledJSON), &disabled)
	return map[string]any{"data": map[string]any{"integrationId": id, "disabledChecks": disabled, "checks": compatFindingCheckStatuses(provider, disabled)}}, nil
}

func (a *App) compatUpdateIntegrationChecks(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var provider string
	var previousJSON string
	if err := a.db.QueryRowContext(ctx, `SELECT provider::text, array_to_json(disabled_checks)::text FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID).Scan(&provider, &previousJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	previous := []string{}
	_ = json.Unmarshal([]byte(previousJSON), &previous)
	disabled := validCompatDisabledChecks(provider, stringSlice(body["disabledChecks"]))
	if _, err := a.db.ExecContext(ctx, `UPDATE integration_connections SET disabled_checks = $1, updated_at = NOW() WHERE id = $2 AND organization_id = $3`, disabled, id, auth.OrganizationID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	a.writeCompatAudit(ctx, auth, "integration.checks.update", "integration_connection", id, map[string]any{"previousDisabled": previous, "nextDisabled": disabled})
	return map[string]any{"data": map[string]any{"integrationId": id, "disabledChecks": disabled, "checks": compatFindingCheckStatuses(provider, disabled)}}, nil
}

func (a *App) compatGoogleMailboxConfig(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var provider string
	var email sql.NullString
	var key sql.NullString
	if err := a.db.QueryRowContext(ctx, `SELECT provider::text, google_mailbox_scan_client_email, encrypted_google_mailbox_scan_private_key FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID).Scan(&provider, &email, &key); err != nil {
		if err == sql.ErrNoRows {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if provider != "GOOGLE_WORKSPACE" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("Mailbox scan configuration is only supported for Google Workspace"))
	}
	return map[string]any{"data": map[string]any{"enabled": email.Valid && key.Valid, "serviceAccountClientEmail": nullStringPtr(email)}}, nil
}

func (a *App) compatUpdateGoogleMailboxConfig(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var provider, external string
	var currentEmail sql.NullString
	var currentKey sql.NullString
	if err := a.db.QueryRowContext(ctx, `SELECT provider::text, external_account_id, google_mailbox_scan_client_email, encrypted_google_mailbox_scan_private_key FROM integration_connections WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID).Scan(&provider, &external, &currentEmail, &currentKey); err != nil {
		if err == sql.ErrNoRows {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if provider != "GOOGLE_WORKSPACE" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("Mailbox scan configuration is only supported for Google Workspace"))
	}

	enabled := boolValue(body["enabled"])
	if !enabled {
		if _, err := a.db.ExecContext(ctx, `UPDATE integration_connections SET google_mailbox_scan_client_email = NULL, encrypted_google_mailbox_scan_private_key = NULL, updated_at = NOW() WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		a.writeCompatAudit(ctx, auth, "integration.google_mailbox_scan.disable", "integration_connection", id, nil)
		return map[string]any{"data": map[string]any{"enabled": false, "serviceAccountClientEmail": nil}}, nil
	}

	nextEmail := strings.TrimSpace(currentEmail.String)
	if emailInput := optionalStringPtr(body, "serviceAccountClientEmail"); emailInput != nil && strings.TrimSpace(*emailInput) != "" {
		nextEmail = strings.TrimSpace(*emailInput)
	}
	if nextEmail == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("Service account client email is required to enable mailbox scanning"))
	}

	keyInput := optionalStringPtr(body, "privateKey")
	keyAAD := compatIntegrationSecretAAD(auth.OrganizationID, "GOOGLE_WORKSPACE", external, "gmail_scan_private_key")
	if keyInput != nil && strings.TrimSpace(*keyInput) != "" {
		encrypted, err := compatEncryptString(strings.TrimSpace(*keyInput), keyAAD)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("google mailbox private key encryption failed"))
		}
		if _, err := a.db.ExecContext(ctx, `UPDATE integration_connections SET google_mailbox_scan_client_email = $1, encrypted_google_mailbox_scan_private_key = $2, updated_at = NOW() WHERE id = $3 AND organization_id = $4`, nextEmail, encrypted, id, auth.OrganizationID); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	} else {
		if !currentKey.Valid || !currentEmail.Valid || strings.TrimSpace(currentEmail.String) != nextEmail {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("Private key is required when enabling mailbox scanning"))
		}
		if _, err := compatDecryptGoogleMailboxPrivateKey(currentKey.String, auth.OrganizationID, id, external); err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("google mailbox private key is unavailable"))
		}
		if _, err := a.db.ExecContext(ctx, `UPDATE integration_connections SET google_mailbox_scan_client_email = $1, updated_at = NOW() WHERE id = $2 AND organization_id = $3`, nextEmail, id, auth.OrganizationID); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	a.writeCompatAudit(ctx, auth, "integration.google_mailbox_scan.enable", "integration_connection", id, map[string]any{"serviceAccountClientEmail": nextEmail})
	return map[string]any{"data": map[string]any{"enabled": true, "serviceAccountClientEmail": nextEmail}}, nil
}

func (a *App) writeCompatAudit(ctx context.Context, auth compatAuth, action, targetType, targetID string, metadata map[string]any) {
	var actor any
	if strings.TrimSpace(auth.UserID) != "" {
		actor = auth.UserID
	}
	var meta any
	if metadata != nil {
		if encoded, err := json.Marshal(metadata); err == nil {
			meta = json.RawMessage(encoded)
		}
	}
	_, _ = a.db.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`, compatID("aud"), auth.OrganizationID, actor, action, targetType, targetID, meta)
}

func (a *App) compatForceSync(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var provider string
	var external string
	err := a.db.QueryRowContext(ctx, `SELECT provider::text, external_account_id FROM integration_connections WHERE id = $1 AND organization_id = $2 AND status = 'CONNECTED'`, id, auth.OrganizationID).Scan(&provider, &external)
	if err == sql.ErrNoRows {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if provider != "GOOGLE_WORKSPACE" {
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("force sync is not implemented for %s yet", strings.ReplaceAll(provider, "_", " ")))
	}
	jobID := compatID("job")
	payload := map[string]any{
		"provider":          provider,
		"integrationId":     id,
		"externalAccountId": external,
		"requestedBy":       auth.UserID,
		"reason":            "manual_force_sync",
	}
	payloadJSON, _ := json.Marshal(payload)
	// Force-sync uses the same durable ingestion queue as provider webhooks. This
	// preserves retry/dead-letter behavior instead of doing synchronous scanning
	// from the request handler.
	_, err = a.db.ExecContext(ctx, `INSERT INTO ingestion_jobs (id, organization_id, integration_id, provider, event_type, source, actor, occurred_at, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at) VALUES ($1,$2,$3,$4,'MANUAL_FORCE_SYNC','aperio.force_sync',$5,NOW(),$6,'QUEUED',0,3,NOW(),NOW(),NOW())`, jobID, auth.OrganizationID, id, provider, auth.Email, json.RawMessage(payloadJSON))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	a.writeCompatAudit(ctx, auth, "integration.force_sync", "integration_connection", id, map[string]any{"provider": provider, "sampleCount": 1, "eventsIngested": 0, "findingsOpened": 0, "sources": []string{"aperio.force_sync"}})
	_, _ = a.db.ExecContext(ctx, `UPDATE integration_connections SET last_sync_at = NOW(), updated_at = NOW() WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID)
	rows, err := a.listIntegrations(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	for _, row := range rows {
		if row.ID == id {
			return map[string]any{"data": row.toProto(), "sync": map[string]any{"sampleCount": 1, "eventsIngested": 0, "findingsOpened": 0, "sources": []string{"aperio.force_sync"}, "jobId": jobID}}, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
}

func (a *App) compatCreateSiem(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	id := compatID("siem")
	kind, name := requiredString(body, "kind"), requiredString(body, "name")
	streams := stringSlice(body["streams"])
	if len(streams) == 0 {
		streams = []string{"FINDINGS"}
	}
	endpointURL := optionalStringPtr(body, "endpointUrl")
	if err := validateCompatSiemEndpoint(endpointURL); err != nil {
		return nil, err
	}
	filePath := optionalStringPtr(body, "filePath")
	// The dispatcher later normalizes export paths against its configured root;
	// this request-time normalization catches traversal payloads early.
	normalizedFilePath, err := normalizeCompatSiemFilePath(filePath)
	if err != nil {
		return nil, err
	}
	filePath = normalizedFilePath
	encryptedToken, err := encryptedOptionalSecret(body, "token", auth.OrganizationID+":siem:"+id+":token")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("SIEM token encryption failed"))
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO siem_destinations (id, organization_id, kind, name, endpoint_url, file_path, index, encrypted_token, streams, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',NOW(),NOW())`, id, auth.OrganizationID, kind, name, endpointURL, filePath, optionalStringPtr(body, "index"), encryptedToken, streams)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	a.writeCompatAudit(ctx, auth, "siem.destination.create", "siem_destination", id, map[string]any{"kind": kind, "name": name, "streams": streams})
	return map[string]any{"data": map[string]any{"id": id, "kind": kind, "name": name, "endpointUrl": endpointURL, "filePath": filePath, "index": optionalStringPtr(body, "index"), "streams": streams, "status": "ACTIVE", "lastDeliveryAt": nil, "lastError": nil, "deliveriesOk": 0, "deliveriesFail": 0, "createdAt": time.Now().UTC().Format(time.RFC3339Nano)}}, nil
}

func (a *App) compatDeleteSiem(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(ctx, `DELETE FROM siem_destinations WHERE id = $1 AND organization_id = $2`, id, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return map[string]any{"data": map[string]bool{"ok": true}}, nil
}

func (a *App) compatTestSiem(ctx context.Context, id string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var exists bool
	if err := a.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM siem_destinations WHERE id = $1 AND organization_id = $2)`, id, auth.OrganizationID).Scan(&exists); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !exists {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("SIEM destination not found"))
	}
	deliveryID := compatID("sdel")
	payload := map[string]any{
		"kind":           "finding",
		"organizationId": auth.OrganizationID,
		"occurredAt":     time.Now().UTC().Format(time.RFC3339Nano),
		"record": map[string]any{
			"test":     true,
			"id":       deliveryID,
			"title":    "Aperio SIEM connectivity test",
			"severity": "INFO",
			"provider": "APERIO",
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	// Connectivity tests enqueue an ordinary SIEM delivery row so the user tests
	// the same dispatcher, lease, serialization, and retry path as real findings.
	_, err := a.db.ExecContext(ctx, `INSERT INTO siem_deliveries (id, organization_id, destination_id, stream, dedupe_key, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at) VALUES ($1,$2,$3,'FINDINGS',$4,$5,'PENDING',0,5,NOW(),NOW(),NOW())`, deliveryID, auth.OrganizationID, id, "test:"+deliveryID, json.RawMessage(payloadJSON))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return map[string]any{"data": map[string]any{"destinationId": id, "ok": true, "message": "SIEM test payload queued for dispatcher", "deliveryId": deliveryID}}, nil
}

func (a *App) compatRemediateFinding(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	action := strings.TrimSpace(requiredString(body, "action"))
	if action == "" || len(action) > 120 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid remediation payload"))
	}
	note := optionalStringPtr(body, "note")
	targetOverride := strings.TrimSpace(stringDefault(body, "targetIdentifier", ""))

	var integrationID, provider, mode, externalAccount, status, encryptedAccessToken, evidenceJSON string
	if err := a.db.QueryRowContext(ctx, `
		SELECT sf.integration_id, ic.provider::text, ic.mode::text, ic.external_account_id, sf.status::text, ic.encrypted_access_token, COALESCE(sf.evidence::text, '{}')
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sf.id = $1 AND sf.organization_id = $2
	`, id, auth.OrganizationID).Scan(&integrationID, &provider, &mode, &externalAccount, &status, &encryptedAccessToken, &evidenceJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("finding not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	connector := findConnectorDefinition(provider)
	if connector == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported connector"))
	}
	if !connectorHasRemediationAction(connector, action) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("action %s is not defined for %s", action, connector.Name))
	}
	if mode != "REMEDIATION" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("this connection is read-only. Reconnect with remediation scopes to enable write actions."))
	}
	accessToken, err := compatDecryptIntegrationSecret(encryptedAccessToken, auth.OrganizationID, integrationID, provider, externalAccount, "access_token")
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("integration credential is unavailable"))
	}

	targetIdentifier := targetOverride
	if action == "slack.revoke_app_install" && targetIdentifier == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("slack.revoke_app_install requires targetIdentifier to be the Slack app id"))
	}
	if targetIdentifier == "" {
		// Prefer the finding's subject/actor evidence when the UI does not supply
		// a target override; falling back to the external account keeps legacy
		// connector actions deterministic.
		var evidence map[string]any
		_ = json.Unmarshal([]byte(evidenceJSON), &evidence)
		if subject, ok := evidence["subject"].(string); ok && subject != "" {
			targetIdentifier = subject
		} else if actor, ok := evidence["actor"].(string); ok && actor != "" {
			targetIdentifier = actor
		} else {
			targetIdentifier = externalAccount
		}
	}

	if action == "slack.revoke_app_install" {
		if err := a.recordRemediationRequested(ctx, auth, id, provider, integrationID, action, targetIdentifier, note); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}

	result := a.executeRemediation(ctx, remediationRequest{
		Provider:          provider,
		Action:            action,
		ExternalAccountID: externalAccount,
		TargetIdentifier:  targetIdentifier,
		IntegrationToken:  accessToken,
	})

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if result.Success {
		var resolver any
		if auth.UserID != "" {
			resolver = auth.UserID
		}
		// Successful provider-side action closes the finding in the same
		// transaction as the audit log so analysts do not see an unaudited status
		// transition.
		if _, err := tx.ExecContext(ctx, `UPDATE security_findings SET status = 'RESOLVED', resolved_at = NOW(), resolved_by_id = $1 WHERE id = $2 AND organization_id = $3`, resolver, id, auth.OrganizationID); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}

	auditAction := "finding.remediate.failure"
	if result.Success {
		auditAction = "finding.remediate.success"
	}
	var noteValue any
	if note != nil {
		noteValue = *note
	}
	metadataFields := map[string]any{
		"provider":          provider,
		"integrationId":     integrationID,
		"actionKey":         action,
		"targetIdentifier":  targetIdentifier,
		"note":              noteValue,
	}
	if result.ProviderRequestID != "" {
		metadataFields["providerRequestId"] = result.ProviderRequestID
	}
	if len(result.Effects) > 0 {
		metadataFields["effects"] = result.Effects
	}
	metadata, err := json.Marshal(metadataFields)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	var actor any
	if auth.UserID != "" {
		actor = auth.UserID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES ($1,$2,$3,$4,'security_finding',$5,$6,NOW())`, compatID("aud"), auth.OrganizationID, actor, auditAction, id, metadata); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	committed = true
	if result.Success {
		resolutionNote := ""
		if note != nil {
			resolutionNote = *note
		}
		a.publishFindingLifecycleEvent(ctx, id, auth.OrganizationID, integrationID, status, "RESOLVED", auth.UserID, resolutionNote, time.Now().UTC())
	}

	return map[string]any{"data": map[string]any{
		"findingId":         id,
		"action":            action,
		"success":           result.Success,
		"message":           result.Message,
		"providerRequestId": result.ProviderRequestID,
		"effects":           result.Effects,
	}}, nil
}

func (a *App) recordRemediationRequested(ctx context.Context, auth compatAuth, findingID, provider, integrationID, action, targetIdentifier string, note *string) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var noteValue any
	if note != nil {
		noteValue = *note
	}
	metadata, err := json.Marshal(map[string]any{
		"provider":         provider,
		"integrationId":    integrationID,
		"actionKey":        action,
		"targetIdentifier": targetIdentifier,
		"note":             noteValue,
	})
	if err != nil {
		return err
	}
	var actor any
	if auth.UserID != "" {
		actor = auth.UserID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES ($1,$2,$3,'finding.remediate.requested','security_finding',$4,$5,NOW())`, compatID("aud"), auth.OrganizationID, actor, findingID, metadata); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (a *App) compatTenantSettings(ctx context.Context, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	row := a.db.QueryRowContext(ctx, `SELECT id, name, slug, notification_email, data_retention_days, critical_risk_threshold, default_sla_hours, auto_resolve_low_severity, enforce_sso_only, webhook_alert_url, created_at, updated_at FROM organizations WHERE id = $1`, auth.OrganizationID)
	data, err := scanOrg(row)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("organization not found"))
	}
	return map[string]any{"data": data}, nil
}

func (a *App) compatUpdateTenantSettings(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(ctx, `UPDATE organizations SET name = COALESCE($1, name), notification_email = COALESCE($2, notification_email), data_retention_days = COALESCE($3, data_retention_days), critical_risk_threshold = COALESCE($4, critical_risk_threshold), default_sla_hours = COALESCE($5, default_sla_hours), auto_resolve_low_severity = COALESCE($6, auto_resolve_low_severity), enforce_sso_only = COALESCE($7, enforce_sso_only), webhook_alert_url = COALESCE($8, webhook_alert_url), updated_at = NOW() WHERE id = $9`, optionalStringPtr(body, "name"), optionalStringPtr(body, "notificationEmail"), optionalInt(body, "dataRetentionDays"), optionalInt(body, "criticalRiskThreshold"), optionalInt(body, "defaultSlaHours"), optionalBool(body, "autoResolveLowSeverity"), optionalBool(body, "enforceSsoOnly"), optionalStringPtr(body, "webhookAlertUrl"), auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return a.compatTenantSettings(ctx, auth)
}

func (a *App) compatMembers(ctx context.Context, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT u.id, u.email, u.display_name, u.is_active, u.password_hash IS NOT NULL, u.mfa_enabled, u.last_login_at, u.is_break_glass, r.name::text, u.created_at FROM users u JOIN roles r ON r.id = u.role_id WHERE u.organization_id = $1 ORDER BY u.created_at ASC`, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	data := []map[string]any{}
	for rows.Next() {
		var id, email, role string
		var display sql.NullString
		var active, hasPassword, mfa, breakGlass bool
		var last sql.NullTime
		var created time.Time
		_ = rows.Scan(&id, &email, &display, &active, &hasPassword, &mfa, &last, &breakGlass, &role, &created)
		state := "INVITED"
		if hasPassword {
			state = "ACTIVE"
		}
		data = append(data, map[string]any{"id": id, "email": email, "displayName": nullStringPtr(display), "isActive": active, "mfaEnabled": mfa, "lastLoginAt": nullTimeCompat(last), "isBreakGlass": breakGlass, "role": role, "authState": state, "pendingActionExpiresAt": nil, "createdAt": created.UTC().Format(time.RFC3339Nano)})
	}
	return map[string]any{"data": data}, nil
}

func (a *App) compatCreateMember(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	email, roleName := strings.ToLower(requiredString(body, "email")), stringDefault(body, "roleName", "VIEWER")
	roleID, _ := a.ensureCompatRole(ctx, auth.OrganizationID, roleName)
	userID := compatID("usr")
	_, err := a.db.ExecContext(ctx, `INSERT INTO users (id, organization_id, role_id, email, display_name, is_active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,TRUE,NOW(),NOW()) ON CONFLICT (organization_id, email) DO UPDATE SET role_id = EXCLUDED.role_id, display_name = COALESCE(EXCLUDED.display_name, users.display_name), is_active = TRUE RETURNING id`, userID, auth.OrganizationID, roleID, email, optionalStringPtr(body, "displayName"))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	token, tokenHash := compatToken()
	expires := time.Now().Add(72 * time.Hour)
	_, _ = a.db.ExecContext(ctx, `INSERT INTO auth_tokens (id, organization_id, user_id, created_by_user_id, purpose, token_hash, expires_at, created_at) VALUES ($1,$2,(SELECT id FROM users WHERE organization_id=$2 AND email=$3),$4,'INVITE',$5,$6,NOW())`, compatID("tok"), auth.OrganizationID, email, auth.UserID, tokenHash, expires)
	members, _ := a.compatMembers(ctx, auth)
	return map[string]any{"data": firstMemberByEmail(members, email), "invitation": map[string]any{"delivery": "manual_link", "url": compatAuthLink("/accept-invite", token), "expiresAt": expires.UTC().Format(time.RFC3339Nano)}}, nil
}

func (a *App) compatCreateMemberReset(ctx context.Context, userID string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	var exists bool
	if err := a.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND organization_id = $2)`, userID, auth.OrganizationID).Scan(&exists); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !exists {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("member not found"))
	}
	token, tokenHash := compatToken()
	expires := time.Now().Add(2 * time.Hour)
	_, err := a.db.ExecContext(ctx, `INSERT INTO auth_tokens (id, organization_id, user_id, created_by_user_id, purpose, token_hash, expires_at, created_at) VALUES ($1,$2,$3,$4,'PASSWORD_RESET',$5,$6,NOW())`, compatID("tok"), auth.OrganizationID, userID, auth.UserID, tokenHash, expires)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	members, _ := a.compatMembers(ctx, auth)
	return map[string]any{"data": firstMemberByID(members, userID), "reset": map[string]any{"delivery": "manual_link", "url": compatAuthLink("/reset-password", token), "expiresAt": expires.UTC().Format(time.RFC3339Nano)}}, nil
}

func (a *App) compatUpdateMemberRole(ctx context.Context, userID string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	roleID, _ := a.ensureCompatRole(ctx, auth.OrganizationID, requiredString(body, "roleName"))
	_, err := a.db.ExecContext(ctx, `UPDATE users SET role_id = $1, updated_at = NOW() WHERE id = $2 AND organization_id = $3`, roleID, userID, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	members, _ := a.compatMembers(ctx, auth)
	return map[string]any{"data": firstMemberByID(members, userID)}, nil
}

func (a *App) compatAuditLogs(ctx context.Context, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT tal.id, tal.action, tal.target_type, tal.target_id, COALESCE(u.email, 'system'), tal.created_at, COALESCE(tal.metadata::text, '{}') FROM tenant_audit_logs tal LEFT JOIN users u ON u.id = tal.actor_user_id WHERE tal.organization_id = $1 ORDER BY tal.created_at DESC LIMIT 50`, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer rows.Close()
	data := []map[string]any{}
	for rows.Next() {
		var id, action, targetType, targetID, actor, metadata string
		var created time.Time
		_ = rows.Scan(&id, &action, &targetType, &targetID, &actor, &created, &metadata)
		var meta any
		_ = json.Unmarshal([]byte(metadata), &meta)
		data = append(data, map[string]any{"id": id, "action": action, "targetType": targetType, "targetId": targetID, "actor": actor, "createdAt": created.UTC().Format(time.RFC3339Nano), "metadata": meta})
	}
	return map[string]any{"data": data}, nil
}

func (a *App) compatSecurityOverview(ctx context.Context, auth compatAuth) (any, error) {
	assets, err := a.listSecurityAssets(ctx, auth.OrganizationID, &aperiov1.ListSecurityAssetsRequest{})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	exceptions, err := a.listRiskExceptions(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	identities, err := a.loadOverviewIdentities(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	findings, err := a.loadOverviewOpenFindings(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	googleIntegrations, err := a.loadOverviewGoogleIntegrations(ctx, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return map[string]any{"data": computeSecurityOverview(identities, assets, exceptions, findings, googleIntegrations)}, nil
}

func (a *App) compatCreateSecurityAsset(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	id := compatID("ast")
	_, err := a.db.ExecContext(ctx, `INSERT INTO security_assets (id, organization_id, integration_id, type, provider, name, summary, external_id, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, last_observed_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12,'UNASSIGNED'),$13,$14,$15,$16,NOW(),NOW())`, id, auth.OrganizationID, optionalStringPtr(body, "integrationId"), requiredString(body, "type"), optionalStringPtr(body, "provider"), requiredString(body, "name"), optionalStringPtr(body, "summary"), optionalStringPtr(body, "externalId"), stringSlice(body["labels"]), stringDefault(body, "criticality", "MEDIUM"), stringDefault(body, "exposureLevel", "INTERNAL"), optionalStringPtr(body, "ownershipStatus"), boolValue(body["containsSensitiveData"]), boolValue(body["isPrivileged"]), intValue(body["riskScore"]), optionalTime(body, "lastObservedAt"))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	rows, _ := a.listSecurityAssets(ctx, auth.OrganizationID, &aperiov1.ListSecurityAssetsRequest{})
	for _, row := range rows {
		if row.ID == id {
			return map[string]any{"data": protoJSON(row.toProto())}, nil
		}
	}
	return map[string]any{"data": map[string]string{"id": id}}, nil
}

func (a *App) compatUpdateSecurityAsset(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(ctx, `UPDATE security_assets SET name = COALESCE($1, name), summary = COALESCE($2, summary), labels = COALESCE($3, labels), criticality = COALESCE($4, criticality), exposure_level = COALESCE($5, exposure_level), ownership_status = COALESCE($6, ownership_status), contains_sensitive_data = COALESCE($7, contains_sensitive_data), is_privileged = COALESCE($8, is_privileged), risk_score = COALESCE($9, risk_score), updated_at = NOW() WHERE id = $10 AND organization_id = $11`, optionalStringPtr(body, "name"), optionalStringPtr(body, "summary"), optionalStringSlice(body, "labels"), optionalStringPtr(body, "criticality"), optionalStringPtr(body, "exposureLevel"), optionalStringPtr(body, "ownershipStatus"), optionalBool(body, "containsSensitiveData"), optionalBool(body, "isPrivileged"), optionalInt(body, "riskScore"), id, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	rows, _ := a.listSecurityAssets(ctx, auth.OrganizationID, &aperiov1.ListSecurityAssetsRequest{})
	for _, row := range rows {
		if row.ID == id {
			return map[string]any{"data": protoJSON(row.toProto())}, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
}

func (a *App) compatCreateRiskException(ctx context.Context, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	id := compatID("rex")
	status := "ACTIVE"
	approvedBy := any(nil)
	approvedAt := any(nil)
	if auth.Role == "OWNER" || auth.Role == "ADMIN" {
		approvedBy = auth.UserID
		approvedAt = time.Now()
	}
	_, err := a.db.ExecContext(ctx, `INSERT INTO risk_exceptions (id, organization_id, asset_id, finding_id, created_by_user_id, approved_by_user_id, title, rationale, compensating_controls, status, expires_at, approved_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())`, id, auth.OrganizationID, optionalStringPtr(body, "assetId"), optionalStringPtr(body, "findingId"), auth.UserID, approvedBy, requiredString(body, "title"), requiredString(body, "rationale"), stringSlice(body["compensatingControls"]), status, optionalTime(body, "expiresAt"), approvedAt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	rows, _ := a.listRiskExceptions(ctx, auth.OrganizationID)
	for _, row := range rows {
		if row.ID == id {
			return map[string]any{"data": protoJSON(row.toProto())}, nil
		}
	}
	return map[string]any{"data": map[string]string{"id": id}}, nil
}

func (a *App) compatUpdateRiskException(ctx context.Context, id string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(ctx, `UPDATE risk_exceptions SET title = COALESCE($1, title), rationale = COALESCE($2, rationale), compensating_controls = COALESCE($3, compensating_controls), status = COALESCE($4, status), expires_at = COALESCE($5, expires_at), updated_at = NOW() WHERE id = $6 AND organization_id = $7`, optionalStringPtr(body, "title"), optionalStringPtr(body, "rationale"), optionalStringSlice(body, "compensatingControls"), optionalStringPtr(body, "status"), optionalTime(body, "expiresAt"), id, auth.OrganizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	rows, _ := a.listRiskExceptions(ctx, auth.OrganizationID)
	for _, row := range rows {
		if row.ID == id {
			return map[string]any{"data": protoJSON(row.toProto())}, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("exception not found"))
}

// Utility helpers.
func compatID(prefix string) string {
	return prefix + "_" + randomURL(18)
}

func compatToken() (string, string) {
	token := randomURL(32)
	return token, hashOpaqueToken(token)
}

func randomURL(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func compatHashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, _ := scrypt.Key([]byte(password), salt, compatPasswordScryptN, compatPasswordScryptR, compatPasswordScryptP, 32)
	return strings.Join([]string{
		"s2",
		strconv.Itoa(compatPasswordScryptN),
		strconv.Itoa(compatPasswordScryptR),
		strconv.Itoa(compatPasswordScryptP),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$")
}

func compatVerifyPassword(password, hash string) bool {
	parts := strings.Split(hash, "$")
	switch {
	case len(parts) == 6 && parts[0] == "s2":
		n, errN := strconv.Atoi(parts[1])
		r, errR := strconv.Atoi(parts[2])
		p, errP := strconv.Atoi(parts[3])
		if errN != nil || errR != nil || errP != nil || !validCompatScryptParams(n, r, p) {
			return false
		}
		return compatVerifyPasswordWithParams(password, parts[4], parts[5], n, r, p)
	case len(parts) == 3 && parts[0] == "s1":
		if compatVerifyPasswordWithParams(password, parts[1], parts[2], compatPasswordScryptN, compatPasswordScryptR, compatPasswordScryptP) {
			return true
		}
		return compatVerifyPasswordWithParams(password, parts[1], parts[2], compatLegacyGoPasswordScryptN, compatPasswordScryptR, compatPasswordScryptP)
	default:
		return false
	}
}

const (
	compatPasswordScryptN         = 16384
	compatLegacyGoPasswordScryptN = 1 << 15
	compatPasswordScryptR         = 8
	compatPasswordScryptP         = 1
	compatPasswordKeyBytes        = 32
)

func validCompatScryptParams(n, r, p int) bool {
	return n >= 2 && n <= 1<<20 && r > 0 && r <= 32 && p > 0 && p <= 8
}

func compatVerifyPasswordWithParams(password, saltPart, hashPart string, n, r, p int) bool {
	salt, err := base64.RawURLEncoding.DecodeString(saltPart)
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(hashPart)
	if err != nil {
		return false
	}
	actual, err := scrypt.Key([]byte(password), salt, n, r, p, compatPasswordKeyBytes)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func compatVerifyTOTP(secret, code string) bool {
	_, ok := compatVerifyTOTPWithCounter(secret, code, sql.NullInt64{})
	return ok
}

func compatVerifyTOTPWithCounter(secret, code string, afterCounter sql.NullInt64) (int64, bool) {
	normalizedCode := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), " ", ""), "-", "")
	if len(normalizedCode) != 6 {
		return 0, false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	counter := time.Now().Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		candidate := counter + offset
		if afterCounter.Valid && candidate <= afterCounter.Int64 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(compatHOTP(key, uint64(candidate))), []byte(normalizedCode)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

func compatHOTP(secret []byte, counter uint64) string {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return strconv.Itoa(value%1000000 + 1000000)[1:]
}

func compatIssueSessionTx(ctx context.Context, tx *sql.Tx, orgID, userID string, mfaVerified bool) (string, error) {
	token, tokenHash := compatToken()
	sessionID := compatID("ses")
	var mfa any
	if mfaVerified {
		mfa = time.Now()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO user_sessions (id, organization_id, user_id, token_hash, expires_at, last_seen_at, mfa_verified_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,NOW(),$6,NOW(),NOW())`, sessionID, orgID, userID, tokenHash, time.Now().Add(12*time.Hour), mfa)
	return sessionID + "." + token, err
}

func compatSessionCookie(token string) string {
	cookie := sessionCookieName + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200"
	if os.Getenv("NODE_ENV") == "production" {
		cookie += "; Secure"
	}
	return cookie
}

func expiredCompatSessionCookie() string {
	return sessionCookieName + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
}

func compatSessionPayload(token string, user compatSessionUser, org compatSessionOrg) map[string]any {
	return map[string]any{"token": token, "user": user, "organization": org}
}

func compatAuthLink(path, token string) string {
	base := strings.TrimRight(envOrDefault("APERIO_WEB_ORIGIN", envOrDefault("NEXT_PUBLIC_APP_BASE_URL", "http://localhost:3000")), "/")
	return base + path + "?token=" + url.QueryEscape(token)
}

func compatBase32(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bytes := make([]byte, n)
	_, _ = rand.Read(bytes)
	var b strings.Builder
	for _, value := range bytes {
		b.WriteByte(alphabet[int(value)%len(alphabet)])
	}
	return b.String()
}

func compatOtpAuthURL(email, secret string) string {
	q := url.Values{"secret": {secret}, "issuer": {"Aperio"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("Aperio:"+email) + "?" + q.Encode()
}

func requiredString(body map[string]any, key string) string {
	if value, ok := body[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func stringDefault(body map[string]any, key, fallback string) string {
	if value := requiredString(body, key); value != "" {
		return value
	}
	return fallback
}

func optionalStringPtr(body map[string]any, key string) *string {
	if value, ok := body[key].(string); ok && strings.TrimSpace(value) != "" {
		trimmed := strings.TrimSpace(value)
		return &trimmed
	}
	return nil
}

func optionalInt(body map[string]any, key string) *int {
	if value, ok := body[key]; ok {
		intValue := intValue(value)
		return &intValue
	}
	return nil
}

func optionalBool(body map[string]any, key string) *bool {
	if value, ok := body[key]; ok {
		boolValue := boolValue(value)
		return &boolValue
	}
	return nil
}

func optionalTime(body map[string]any, key string) any {
	value := requiredString(body, key)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return parsed
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	default:
		return 0
	}
}

func boolValue(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func stringSlice(value any) []string {
	if typed, ok := value.([]string); ok {
		return typed
	}
	raw, ok := value.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func optionalStringSlice(body map[string]any, key string) any {
	if _, ok := body[key]; !ok {
		return nil
	}
	return stringSlice(body[key])
}

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func nullTimeCompat(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time.UTC().Format(time.RFC3339Nano)
}

func scanOrg(row *sql.Row) (map[string]any, error) {
	var id, name, slug string
	var email, webhook sql.NullString
	var retention, threshold, sla int
	var autoResolve, sso bool
	var created, updated time.Time
	if err := row.Scan(&id, &name, &slug, &email, &retention, &threshold, &sla, &autoResolve, &sso, &webhook, &created, &updated); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "slug": slug, "notificationEmail": nullStringPtr(email), "dataRetentionDays": retention, "criticalRiskThreshold": threshold, "defaultSlaHours": sla, "autoResolveLowSeverity": autoResolve, "enforceSsoOnly": sso, "webhookAlertUrl": nullStringPtr(webhook), "createdAt": created.UTC().Format(time.RFC3339Nano), "updatedAt": updated.UTC().Format(time.RFC3339Nano)}, nil
}

func (a *App) ensureCompatRole(ctx context.Context, orgID, role string) (string, error) {
	var id string
	err := a.db.QueryRowContext(ctx, `SELECT id FROM roles WHERE organization_id = $1 AND name = $2`, orgID, role).Scan(&id)
	if err == nil {
		return id, nil
	}
	id = compatID("role")
	_, err = a.db.ExecContext(ctx, `INSERT INTO roles (id, organization_id, name, permissions, created_at, updated_at) VALUES ($1,$2,$3,ARRAY['read']::text[],NOW(),NOW())`, id, orgID, role)
	return id, err
}

func requireCompatRole(auth compatAuth, allowed ...string) error {
	for _, role := range allowed {
		if auth.Role == role {
			return nil
		}
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("forbidden"))
}

func validateCompatExternalAccount(provider, externalAccountID string) error {
	if strings.EqualFold(strings.TrimSpace(provider), "OKTA") {
		return validateCompatOktaDomain(externalAccountID)
	}
	return nil
}

func validateCompatOktaDomain(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("Okta domain is required"))
	}
	host := trimmed
	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("Okta domain must be a bare HTTPS host"))
		}
		host = parsed.Host
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "/") || strings.Contains(host, "@") || strings.Contains(host, ":") {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("Okta domain must be a bare host name"))
	}
	if ip := net.ParseIP(host); ip != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("Okta domain must be an Okta-hosted domain"))
	}
	if !isAllowedCompatOktaHost(host) {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("Okta domain must end in okta.com, oktapreview.com, okta-emea.com, or okta-gov.com"))
	}
	return nil
}

func isAllowedCompatOktaHost(host string) bool {
	for _, suffix := range []string{".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com"} {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

func validateCompatSiemEndpoint(raw *string) error {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil
	}
	parsed, err := url.Parse(strings.TrimSpace(*raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid SIEM endpoint URL"))
	}
	if parsed.Scheme != "https" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint URL must use HTTPS"))
	}
	host := normalizeCompatHostname(parsed.Hostname())
	if host == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint URL hostname is required"))
	}
	if isBlockedCompatHostname(host) {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint cannot target private hosts"))
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateCompatIP(ip) {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint cannot target private addresses"))
		}
		*raw = parsed.String()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint hostname could not be resolved"))
	}
	for _, address := range addresses {
		if isPrivateCompatIP(address.IP) {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("SIEM endpoint cannot resolve to private addresses"))
		}
	}
	*raw = parsed.String()
	return nil
}

func normalizeCompatHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func isBlockedCompatHostname(host string) bool {
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return true
	}
	for _, suffix := range []string{".internal", ".local", ".localhost", ".localdomain", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func isPrivateCompatIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		first, second, third := int(v4[0]), int(v4[1]), int(v4[2])
		return first == 0 ||
			first == 10 ||
			first == 127 ||
			(first == 100 && second >= 64 && second <= 127) ||
			(first == 169 && second == 254) ||
			(first == 172 && second >= 16 && second <= 31) ||
			(first == 192 && second == 0 && third == 0) ||
			(first == 192 && second == 0 && third == 2) ||
			(first == 192 && second == 168) ||
			(first == 198 && (second == 18 || second == 19)) ||
			(first == 198 && second == 51 && third == 100) ||
			(first == 203 && second == 0 && third == 113) ||
			first >= 224
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		strings.HasPrefix(strings.ToLower(ip.String()), "2001:db8")
}

func normalizeCompatSiemFilePath(raw *string) (*string, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	root := strings.TrimSpace(os.Getenv("APERIO_SIEM_EXPORT_DIR"))
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(cwd, "var", "siem-exports")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(*raw)
	candidate := trimmed
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." || filepath.IsAbs(relative) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("file path must stay within %s", root))
	}
	return &candidate, nil
}

func compatResolveEncryptionKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("APERIO_ENCRYPTION_KEY"))
	if raw == "" {
		return nil, errors.New("APERIO_ENCRYPTION_KEY is required")
	}
	// Match the TypeScript vault format exactly: production requires explicit
	// key encoding, while local development may derive a 32-byte key from a
	// passphrase for convenience.
	switch {
	case strings.HasPrefix(raw, "base64:"):
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "base64:"))
		if err != nil {
			return nil, err
		}
		if len(key) != compatEncryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	case strings.HasPrefix(raw, "base64url:"):
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "base64url:"))
		if err != nil {
			return nil, err
		}
		if len(key) != compatEncryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	case strings.HasPrefix(raw, "hex:"):
		key, err := hex.DecodeString(strings.TrimPrefix(raw, "hex:"))
		if err != nil {
			return nil, err
		}
		if len(key) != compatEncryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	default:
		if os.Getenv("NODE_ENV") == "production" {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must use base64:, base64url:, or hex: encoding in production")
		}
		return scrypt.Key([]byte(raw), []byte("aperio-token-vault"), 16384, 8, 1, compatEncryptionKeyBytes)
	}
}

func compatEncryptString(plaintext string, additionalAuthenticatedData string) (string, error) {
	nonce := make([]byte, compatEncryptionNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return compatEncryptStringWithNonce(plaintext, additionalAuthenticatedData, nonce)
}

func compatEncryptStringWithNonce(plaintext string, additionalAuthenticatedData string, nonce []byte) (string, error) {
	if plaintext == "" {
		return "", errors.New("cannot encrypt an empty string")
	}
	if len(nonce) != compatEncryptionNonceBytes {
		return "", errors.New("invalid encryption nonce length")
	}
	key, err := compatResolveEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Additional authenticated data binds tokens to their organization/provider
	// context without exposing that context in the encrypted envelope.
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(additionalAuthenticatedData))
	tagStart := len(sealed) - gcm.Overhead()
	envelope := compatEncryptedEnvelope{
		Version:    1,
		Algorithm:  compatEncryptionAlgorithm,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Tag:        base64.RawURLEncoding.EncodeToString(sealed[tagStart:]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed[:tagStart]),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func compatDecryptString(encrypted string, additionalAuthenticatedData string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	var envelope compatEncryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", err
	}
	if envelope.Version != 1 || envelope.Algorithm != compatEncryptionAlgorithm {
		return "", errors.New("unsupported encrypted value")
	}
	iv, err := base64.RawURLEncoding.DecodeString(envelope.IV)
	if err != nil {
		return "", err
	}
	tag, err := base64.RawURLEncoding.DecodeString(envelope.Tag)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", err
	}
	key, err := compatResolveEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(iv) != gcm.NonceSize() {
		return "", errors.New("invalid encryption nonce length")
	}
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(additionalAuthenticatedData))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func nestedString(body map[string]any, objectKey string, key string) string {
	nested, _ := body[objectKey].(map[string]any)
	if nested == nil {
		return ""
	}
	return requiredString(nested, key)
}

func asMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		if typed != nil {
			return typed
		}
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	}
	return map[string]any{}
}

func compatIntegrationSecretAAD(organizationID string, provider string, externalAccountID string, suffix string) string {
	// Keep AAD stable across reconnects: externalAccountID is the provider-owned
	// tenant identity and therefore survives integration row replacement.
	return organizationID + ":" + provider + ":" + externalAccountID + ":" + suffix
}

func compatLegacyIntegrationSecretAAD(organizationID string, integrationID string, suffix string) string {
	return organizationID + ":" + integrationID + ":" + suffix
}

func compatDecryptIntegrationSecret(encryptedValue string, organizationID string, integrationID string, provider string, externalAccountID string, suffix string) (string, error) {
	canonical, err := compatDecryptString(encryptedValue, compatIntegrationSecretAAD(organizationID, provider, externalAccountID, suffix))
	if err == nil {
		return canonical, nil
	}
	if strings.TrimSpace(integrationID) == "" {
		return "", err
	}
	legacy, legacyErr := compatDecryptString(encryptedValue, compatLegacyIntegrationSecretAAD(organizationID, integrationID, suffix))
	if legacyErr == nil {
		return legacy, nil
	}
	return "", err
}

func compatDecryptGoogleMailboxPrivateKey(encryptedValue string, organizationID string, integrationID string, externalAccountID string) (string, error) {
	canonical, err := compatDecryptString(encryptedValue, compatIntegrationSecretAAD(organizationID, "GOOGLE_WORKSPACE", externalAccountID, "gmail_scan_private_key"))
	if err == nil {
		return canonical, nil
	}
	if strings.TrimSpace(integrationID) == "" {
		return "", err
	}
	legacy, legacyErr := compatDecryptString(encryptedValue, compatLegacyIntegrationSecretAAD(organizationID, integrationID, "google_mailbox_private_key"))
	if legacyErr == nil {
		return legacy, nil
	}
	return "", err
}

func encryptedOptionalSecret(body map[string]any, key string, aad string) (*string, error) {
	value := requiredString(body, key)
	if value == "" {
		return nil, nil
	}
	encrypted, err := compatEncryptString(value, aad)
	if err != nil {
		return nil, err
	}
	return &encrypted, nil
}

func firstMemberByEmail(result any, email string) any {
	data, _ := result.(map[string]any)["data"].([]map[string]any)
	for _, item := range data {
		if item["email"] == email {
			return item
		}
	}
	return nil
}

func firstMemberByID(result any, id string) any {
	data, _ := result.(map[string]any)["data"].([]map[string]any)
	for _, item := range data {
		if item["id"] == id {
			return item
		}
	}
	return nil
}

func protoJSON(value any) map[string]any {
	bytes, _ := json.Marshal(value)
	out := map[string]any{}
	_ = json.Unmarshal(bytes, &out)
	return out
}
