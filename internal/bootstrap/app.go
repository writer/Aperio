package bootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/gen/aperio/v1/aperiov1connect"
	"github.com/writer/aperio/internal/config"
)

const sessionCookieName = "aperio_session"

// App owns the Go/ConnectRPC HTTP surface. It deliberately keeps only
// infrastructural dependencies here so endpoint implementations stay easy to
// move from the current TypeScript API into Go one route at a time.
type App struct {
	cfg config.Config
	db  *sql.DB
	mux *http.ServeMux
}

// dashboardMetrics mirrors the existing web dashboard response shape. Keeping
// this internal shape separate from the generated protobuf type lets the SQL
// aggregation evolve without leaking database-specific details into contracts.
type dashboardMetrics struct {
	TotalRiskScore       int32 `json:"totalRiskScore"`
	OpenCriticalFindings int32 `json:"openCriticalFindings"`
	ConnectedApps        int32 `json:"connectedApps"`
	EventIngestionRate   int32 `json:"eventIngestionRate"`
}

type riskFinding struct {
	RiskScore  int
	Severity   string
	DetectedAt time.Time
	Evidence   map[string]any
	Provider   string
}

// NewApp wires routes but does not open network sockets. Tests can mount the
// returned handler directly, while cmd/aperio decides how to listen in runtime.
func NewApp(cfg config.Config, db *sql.DB) *App {
	app := &App{
		cfg: cfg,
		db:  db,
		mux: http.NewServeMux(),
	}
	app.routes()
	return app
}

// Handler returns the complete HTTP handler stack. CORS is applied outside the
// route mux so every ConnectRPC method and the liveness endpoint share the same
// browser boundary.
func (a *App) Handler() http.Handler {
	return a.withCORS(a.mux)
}

// routes mounts the dependency-free liveness endpoint plus the generated
// ConnectRPC handler. The generated handler provides binary protobuf, JSON,
// gRPC, and gRPC-Web compatibility for the same service implementation.
func (a *App) routes() {
	a.mux.HandleFunc("/healthz", a.handleHealthz)
	path, handler := aperiov1connect.NewAperioServiceHandler(a)
	a.mux.Handle(path, handler)
}

// handleHealthz intentionally avoids database access. Orchestrators can use it
// as a cheap process liveness probe without coupling restarts to Postgres state.
func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "aperio-go-connect"})
}

// CheckHealth is the first ConnectRPC method exposed by the Go service. It
// matches Cerebro's generated-handler pattern and gives TypeScript clients a
// stable endpoint to verify transport compatibility.
func (a *App) CheckHealth(
	context.Context,
	*connect.Request[aperiov1.CheckHealthRequest],
) (*connect.Response[aperiov1.CheckHealthResponse], error) {
	return connect.NewResponse(&aperiov1.CheckHealthResponse{
		Status:  "ok",
		Service: "aperio-go-connect",
	}), nil
}

// GetDashboardMetrics is the first product endpoint migrated behind
// ConnectRPC. It preserves the existing tenant cookie model so the web client
// can opt in via NEXT_PUBLIC_CONNECT_API_BASE_URL without changing login flow.
func (a *App) GetDashboardMetrics(
	ctx context.Context,
	req *connect.Request[aperiov1.GetDashboardMetricsRequest],
) (*connect.Response[aperiov1.GetDashboardMetricsResponse], error) {
	if a.db == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("database not configured"))
	}
	organizationID, err := a.organizationIDFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	metrics, err := a.dashboardMetrics(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("dashboard metrics unavailable"))
	}
	return connect.NewResponse(&aperiov1.GetDashboardMetricsResponse{
		Data: &aperiov1.DashboardMetrics{
			TotalRiskScore:       metrics.TotalRiskScore,
			OpenCriticalFindings: metrics.OpenCriticalFindings,
			ConnectedApps:        metrics.ConnectedApps,
			EventIngestionRate:   metrics.EventIngestionRate,
		},
	}), nil
}

// organizationIDFromSession validates Aperio's HttpOnly cookie session against
// the same user_sessions table used by the TypeScript API. It accepts only live,
// unrevoked sessions for active users, respects MFA completion, and enforces the
// same idle-timeout control before returning the tenant boundary.
func (a *App) organizationIDFromSession(ctx context.Context, header http.Header) (string, error) {
	token := sessionCookie(header.Get("Cookie"))
	if token == "" {
		return "", errors.New("missing session")
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("invalid session")
	}
	tokenHash := hashOpaqueToken(parts[1])

	var organizationID, sessionID string
	var lastSeenAt time.Time
	err := a.db.QueryRowContext(ctx, `
		SELECT us.id, us.organization_id, us.last_seen_at
		FROM user_sessions us
		JOIN users u ON u.id = us.user_id
		WHERE us.id = $1
		  AND us.token_hash = $2
		  AND us.revoked_at IS NULL
		  AND us.expires_at > NOW()
		  AND u.is_active = TRUE
		  AND (u.mfa_enabled = FALSE OR us.mfa_verified_at IS NOT NULL)
	`, parts[0], tokenHash).Scan(&sessionID, &organizationID, &lastSeenAt)
	if err != nil {
		return "", err
	}
	if time.Since(lastSeenAt) > time.Duration(a.cfg.SessionIdleMinutes)*time.Minute {
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, sessionID)
		return "", errors.New("session idle timeout")
	}
	if time.Since(lastSeenAt) > time.Minute {
		_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_at = NOW() WHERE id = $1`, sessionID)
	}
	return organizationID, nil
}

// sessionCookie extracts the opaque session token from the Cookie header without
// depending on Express-style middleware. Keeping this small and explicit makes
// the cross-runtime auth boundary auditable.
func sessionCookie(header string) string {
	for _, entry := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if ok && name == sessionCookieName {
			return value
		}
	}
	return ""
}

// dashboardMetrics performs the read-side aggregation for the dashboard. The
// query is intentionally tenant-scoped and read-only so it is a safe first slice
// to serve from the Go runtime before moving mutation-heavy endpoints.
func (a *App) dashboardMetrics(ctx context.Context, organizationID string) (dashboardMetrics, error) {
	var metrics dashboardMetrics
	oneMinuteAgo := time.Now().Add(-1 * time.Minute)
	findings, err := a.openFindings(ctx, organizationID)
	if err != nil {
		return metrics, err
	}
	metrics.TotalRiskScore = int32(aggregateRiskScore(findings))
	row := a.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE sf.status = 'OPEN' AND sf.severity = 'CRITICAL')::int,
			(SELECT COUNT(*)::int FROM integration_connections ic WHERE ic.organization_id = $1 AND ic.status = 'CONNECTED'),
			(SELECT COUNT(*)::int FROM ingested_events ie WHERE ie.organization_id = $1 AND ie.created_at >= $2)
		FROM security_findings sf
		WHERE sf.organization_id = $1
	`, organizationID, oneMinuteAgo)
	err = row.Scan(
		&metrics.OpenCriticalFindings,
		&metrics.ConnectedApps,
		&metrics.EventIngestionRate,
	)
	return metrics, err
}

// openFindings loads the same finding fields used by the TypeScript risk
// scorer. Keeping the selection explicit prevents the Go endpoint from drifting
// into raw database aggregates that do not match the product metric.
func (a *App) openFindings(ctx context.Context, organizationID string) ([]riskFinding, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT sf.risk_score, sf.severity::text, sf.detected_at, sf.evidence, ic.provider::text
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sf.organization_id = $1 AND sf.status = 'OPEN'
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []riskFinding
	for rows.Next() {
		var finding riskFinding
		var evidenceBytes []byte
		if err := rows.Scan(
			&finding.RiskScore,
			&finding.Severity,
			&finding.DetectedAt,
			&evidenceBytes,
			&finding.Provider,
		); err != nil {
			return nil, err
		}
		if len(evidenceBytes) > 0 {
			_ = json.Unmarshal(evidenceBytes, &finding.Evidence)
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func aggregateRiskScore(findings []riskFinding) int {
	if len(findings) == 0 {
		return 0
	}
	scores := make([]int, 0, len(findings))
	criticalCount := 0
	highCount := 0
	recentHighCount := 0
	providers := map[string]struct{}{}
	for _, finding := range findings {
		score := calculateFindingRiskScore(finding)
		scores = append(scores, score)
		if finding.Severity == "CRITICAL" {
			criticalCount++
		}
		if finding.Severity == "HIGH" {
			highCount++
		}
		if score >= 70 && time.Since(finding.DetectedAt) <= 7*24*time.Hour {
			recentHighCount++
		}
		if provider := providerFromFinding(finding); provider != "" {
			providers[provider] = struct{}{}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(scores)))
	highest := scores[0]
	residual := 0.0
	weights := []float64{0.2, 0.12, 0.08, 0.05}
	for index, score := range scores[1:] {
		weight := 0.03
		if index < len(weights) {
			weight = weights[index]
		}
		residual += float64(score) * weight
	}
	return clampInt(int(math.Round(
		float64(highest)*0.72+
			residual+
			float64(minInt(14, criticalCount*6+highCount*2))+
			float64(minInt(8, maxInt(0, len(providers)-1)*2))+
			float64(minInt(8, recentHighCount*2)),
	)), 0, 100)
}

func calculateFindingRiskScore(finding riskFinding) int {
	score := maxInt(clampInt(finding.RiskScore, 0, 100), severityFloor(finding.Severity))
	bonus := 0

	grantedRole := strings.ToLower(stringEvidence(finding.Evidence, "grantedRole", "role"))
	if strings.Contains(grantedRole, "super admin") {
		bonus += 10
	} else if strings.Contains(grantedRole, "admin") {
		bonus += 6
	}
	if boolEvidenceEquals(finding.Evidence, "delegatedAdmin", true) {
		bonus += 4
	}
	if boolEvidenceEquals(finding.Evidence, "mfaEnrolled", false) {
		bonus += 10
	}
	if boolEvidenceEquals(finding.Evidence, "mfaEnforced", false) {
		bonus += 8
	}

	visibility := strings.ToLower(stringEvidence(finding.Evidence, "visibility", "exposureLevel"))
	if strings.Contains(visibility, "public") ||
		strings.Contains(visibility, "anyone") ||
		strings.Contains(visibility, "shared_externally") {
		bonus += 10
	} else if strings.Contains(visibility, "external") {
		bonus += 6
	}

	riskReason := strings.ToLower(stringEvidence(finding.Evidence, "riskReason"))
	if strings.Contains(riskReason, "full mailbox") || strings.Contains(riskReason, "mailbox-settings") {
		bonus += 8
	} else if strings.Contains(riskReason, "mailbox") {
		bonus += 4
	}

	scopeCount := numberEvidence(finding.Evidence, "scopeCount", len(stringArrayEvidence(finding.Evidence, "scopes")))
	bonus += minInt(8, maxInt(0, scopeCount-1))

	delegateCount := numberEvidence(finding.Evidence, "delegateCount", len(stringArrayEvidence(finding.Evidence, "delegates")))
	sendAsCount := numberEvidence(finding.Evidence, "sendAsCount", len(stringArrayEvidence(finding.Evidence, "sendAsAliases")))
	bonus += minInt(8, delegateCount*2+sendAsCount*2)

	if len(stringArrayEvidence(finding.Evidence, "comboKinds")) > 1 {
		bonus += 8
	}
	bonus += minInt(12, externalEmailCount(finding.Evidence)*3)

	if time.Since(finding.DetectedAt) <= 24*time.Hour {
		bonus += 4
	} else if time.Since(finding.DetectedAt) <= 7*24*time.Hour {
		bonus += 2
	} else if time.Since(finding.DetectedAt) > 90*24*time.Hour {
		bonus -= 8
	} else if time.Since(finding.DetectedAt) > 30*24*time.Hour {
		bonus -= 4
	}
	return clampInt(score+bonus, 0, 100)
}

func severityFloor(severity string) int {
	switch severity {
	case "CRITICAL":
		return 88
	case "HIGH":
		return 68
	case "MEDIUM":
		return 45
	case "LOW":
		return 25
	default:
		return 10
	}
}

func stringEvidence(evidence map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := evidence[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolEvidenceEquals(evidence map[string]any, key string, expected bool) bool {
	value, ok := evidence[key].(bool)
	return ok && value == expected
}

func numberEvidence(evidence map[string]any, key string, fallback int) int {
	switch value := evidence[key].(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fallback
		}
		return int(value)
	case json.Number:
		parsed, err := value.Int64()
		if err == nil {
			return int(parsed)
		}
	}
	return fallback
}

func stringArrayEvidence(evidence map[string]any, key string) []string {
	value, ok := evidence[key]
	if !ok {
		return nil
	}
	if entry, ok := value.(string); ok {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	}
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	entries := make([]string, 0, len(values))
	for _, raw := range values {
		entry, ok := raw.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	return entries
}

func providerFromFinding(finding riskFinding) string {
	if finding.Provider != "" {
		return finding.Provider
	}
	return stringEvidence(finding.Evidence, "provider")
}

func externalEmailCount(evidence map[string]any) int {
	anchorEmail := firstString(
		stringEvidence(evidence, "mailbox"),
		stringEvidence(evidence, "user"),
		stringEvidence(evidence, "actor"),
		stringEvidence(evidence, "target"),
	)
	anchorDomain := domainFromEmail(anchorEmail)
	if anchorDomain == "" {
		return 0
	}

	candidates := append([]string{}, stringArrayEvidence(evidence, "delegates")...)
	candidates = append(candidates, stringArrayEvidence(evidence, "sendAsAliases")...)
	candidates = append(candidates, stringArrayEvidence(evidence, "externalSendAsAliases")...)
	candidates = append(candidates,
		stringEvidence(evidence, "forwardedTo"),
		stringEvidence(evidence, "recoveryEmail"),
		stringEvidence(evidence, "externalActor"),
		stringEvidence(evidence, "delegate"),
	)
	external := map[string]struct{}{}
	for _, email := range candidates {
		domain := domainFromEmail(email)
		if domain != "" && domain != anchorDomain {
			external[strings.ToLower(strings.TrimSpace(email))] = struct{}{}
		}
	}
	return len(external)
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func domainFromEmail(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func clampInt(value, minValue, maxValue int) int {
	return minInt(maxInt(value, minValue), maxValue)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// hashOpaqueToken mirrors packages/security/src/crypto.ts. Session rows store
// only SHA-256 hashes of raw token material; the Go service must hash the cookie
// suffix before comparing it in SQL.
func hashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// withCORS allows the browser-based Connect client to include the HttpOnly
// session cookie. It only reflects configured web origins and treats OPTIONS as
// a transport preflight, leaving auth enforcement to individual RPCs.
func (a *App) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin != "" && a.isAllowedWebOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "content-type, connect-protocol-version, x-user-agent")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if isUnsafeMethod(r.Method) && sessionCookie(r.Header.Get("Cookie")) != "" && !a.hasAllowedRequestOrigin(r) {
			writeError(w, http.StatusForbidden, "invalid request origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (a *App) hasAllowedRequestOrigin(r *http.Request) bool {
	origin := strings.TrimRight(r.Header.Get("Origin"), "/")
	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer != "" {
			parsed, err := url.Parse(referer)
			if err == nil {
				origin = parsed.Scheme + "://" + parsed.Host
			}
		}
	}
	return origin != "" && a.isAllowedWebOrigin(origin)
}

func (a *App) isAllowedWebOrigin(origin string) bool {
	normalized := strings.TrimRight(strings.TrimSpace(origin), "/")
	for _, allowed := range strings.Split(a.cfg.WebOrigin, ",") {
		if normalized == strings.TrimRight(strings.TrimSpace(allowed), "/") {
			return true
		}
	}
	return false
}

// writeJSON is used only by non-Connect compatibility endpoints such as
// /healthz. ConnectRPC responses are encoded by the generated handlers.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError keeps liveness and pre-Connect utility endpoints consistent with
// the existing REST API's simple {error} response shape.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
