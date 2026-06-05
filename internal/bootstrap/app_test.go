package bootstrap

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/gen/aperio/v1/aperiov1connect"
	"github.com/writer/aperio/internal/config"
)

// TestCheckHealthConnectEndpoint exercises the generated Go Connect client
// against the in-process server. This catches handler registration drift without
// requiring Postgres.
func TestCheckHealthConnectEndpoint(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := aperiov1connect.NewAperioServiceClient(server.Client(), server.URL)

	resp, err := client.CheckHealth(
		context.Background(),
		connect.NewRequest(&aperiov1.CheckHealthRequest{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Status != "ok" {
		t.Fatalf("expected ok, got %s", resp.Msg.Status)
	}
}

func TestAggregateRiskScoreMatchesClampedPostureShape(t *testing.T) {
	score := aggregateRiskScore([]riskFinding{
		{
			RiskScore:  95,
			Severity:   "CRITICAL",
			DetectedAt: nowMinus(t, time.Hour),
			Evidence:   map[string]any{"visibility": "public"},
			Provider:   "GITHUB",
		},
		{
			RiskScore:  90,
			Severity:   "HIGH",
			DetectedAt: nowMinus(t, 2*time.Hour),
			Provider:   "SLACK",
		},
	})

	if score < 1 || score > 100 {
		t.Fatalf("expected clamped posture score, got %d", score)
	}
	if score == 185 {
		t.Fatal("expected weighted aggregate, not raw risk score sum")
	}
}

func TestCalculateFindingRiskScoreMirrorsTypeScriptEvidenceBonuses(t *testing.T) {
	score := calculateFindingRiskScore(riskFinding{
		RiskScore:  10,
		Severity:   "LOW",
		DetectedAt: nowMinus(t, 40*24*time.Hour),
		Evidence: map[string]any{
			"mailbox":     "alice@example.com",
			"role":        "admin",
			"mfaEnrolled": false,
			"visibility":  "external",
			"riskReason":  "mailbox delegate",
			"scopeCount":  float64(3),
			"delegates":   []any{"bob@external.example"},
			"comboKinds":  []any{"oauth_scope", "mailbox_delegate"},
		},
	})

	if score != 62 {
		t.Fatalf("expected TS-compatible score 62, got %d", score)
	}
}

// TestConnectCORSPreflight verifies browser clients can call ConnectRPC with
// credentials. The allowed origin must match exactly because session cookies are
// cross-runtime auth material.
func TestConnectCORSPreflight(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(http.MethodOptions, "/aperio.v1.AperioService/GetDashboardMetrics", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("expected matching CORS origin")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("expected credentialed CORS")
	}
}

func TestConnectCORSPreflightAllowsCommaSeparatedOrigins(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "https://app.example.com, http://localhost:3000/"}, nil)
	req := httptest.NewRequest(http.MethodOptions, "/aperio.v1.AperioService/GetDashboardMetrics", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("expected matching CORS origin from allow-list")
	}
}

func TestCookieBackedConnectRequiresAllowedOrigin(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(
		http.MethodPost,
		"/aperio.v1.AperioService/GetDashboardMetrics",
		bytes.NewBufferString("{}"),
	)
	req.Header.Set("Cookie", "aperio_session=session.raw")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func nowMinus(t *testing.T, duration time.Duration) time.Time {
	t.Helper()
	return time.Now().Add(-duration)
}
