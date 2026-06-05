package bootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
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
// unrevoked sessions for active users and respects MFA completion.
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

	var organizationID string
	err := a.db.QueryRowContext(ctx, `
		SELECT us.organization_id
		FROM user_sessions us
		JOIN users u ON u.id = us.user_id
		WHERE us.id = $1
		  AND us.token_hash = $2
		  AND us.revoked_at IS NULL
		  AND us.expires_at > NOW()
		  AND u.is_active = TRUE
		  AND (u.mfa_enabled = FALSE OR us.mfa_verified_at IS NOT NULL)
	`, parts[0], tokenHash).Scan(&organizationID)
	if err != nil {
		return "", err
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
	row := a.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN sf.status = 'OPEN' THEN sf.risk_score ELSE 0 END), 0)::int,
			COUNT(*) FILTER (WHERE sf.status = 'OPEN' AND sf.severity = 'CRITICAL')::int,
			(SELECT COUNT(*)::int FROM integration_connections ic WHERE ic.organization_id = $1 AND ic.status = 'CONNECTED'),
			(SELECT COUNT(*)::int FROM ingested_events ie WHERE ie.organization_id = $1 AND ie.created_at >= $2)
		FROM security_findings sf
		WHERE sf.organization_id = $1
	`, organizationID, oneMinuteAgo)
	err := row.Scan(
		&metrics.TotalRiskScore,
		&metrics.OpenCriticalFindings,
		&metrics.ConnectedApps,
		&metrics.EventIngestionRate,
	)
	return metrics, err
}

// hashOpaqueToken mirrors packages/security/src/crypto.ts. Session rows store
// only SHA-256 hashes of raw token material; the Go service must hash the cookie
// suffix before comparing it in SQL.
func hashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// withCORS allows the browser-based Connect client to include the HttpOnly
// session cookie. It only reflects the configured web origin and treats OPTIONS
// as a transport preflight, leaving auth enforcement to individual RPCs.
func (a *App) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin != "" && origin == a.cfg.WebOrigin {
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
		next.ServeHTTP(w, r)
	})
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
