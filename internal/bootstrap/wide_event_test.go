package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/telemetry"
)

func TestProcedureMethod(t *testing.T) {
	cases := map[string]string{
		"/aperio.v1.AperioService/ListFindings": "ListFindings",
		"/aperio.v1.AperioService/CallApi":      "CallApi",
		"ListFindings":                          "ListFindings",
		"":                                      "",
	}
	for procedure, want := range cases {
		if got := procedureMethod(procedure); got != want {
			t.Errorf("procedureMethod(%q) = %q, want %q", procedure, got, want)
		}
	}
}

func TestNormalizeCompatRoute(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/integrations/catalog", "/api/v1/integrations/catalog"},
		{"/api/v1/siem/catalog", "/api/v1/siem/catalog"},
		{"/api/v1/auth/login", "/api/v1/auth/login"},
		{"/api/v1/integrations/google-workspace/oauth/start", "/api/v1/integrations/google-workspace/oauth/start"},
		{"/api/v1/integrations/clf2x9q1z0000abcd1234efgh/checks", "/api/v1/integrations/:id/checks"},
		{"/api/v1/integrations/clf2x9q1z0000abcd1234efgh/google-mailbox-scan", "/api/v1/integrations/:id/google-mailbox-scan"},
		{"/api/v1/findings/clf2x9q1z0000abcd1234efgh/remediate", "/api/v1/findings/:id/remediate"},
		{"/api/v1/findings/clf2x9q1z0000abcd1234efgh", "/api/v1/findings/:id"},
		{"/api/v1/admin/members/org_demo_000000000000000000000001/role", "/api/v1/admin/members/:id/role"},
		{"/api/v1/siem/123e4567-e89b-12d3-a456-426614174000/test", "/api/v1/siem/:id/test"},
		{"/api/v1/findings/clf2x9q1z0000abcd1234efgh?cursor=abc", "/api/v1/findings/:id"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		if got := normalizeCompatRoute(tc.path); got != tc.want {
			t.Errorf("normalizeCompatRoute(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestCollectorSnapshotCopiesAnnotations(t *testing.T) {
	ctx, collector := telemetry.NewCollector(context.Background())

	got, ok := telemetry.CollectorFrom(ctx)
	if !ok || got != collector {
		t.Fatal("expected collector to be retrievable from context")
	}

	collector.SetOrganization("org_123")
	collector.Dimension("http.route.query.status", "OPEN")
	collector.Dimension("ignored.empty", "   ")
	collector.Measurement("result.count", 7)

	org, dimensions, measurements := collector.Snapshot()
	if org != "org_123" {
		t.Fatalf("organization = %q, want org_123", org)
	}
	if dimensions["http.route.query.status"] != "OPEN" {
		t.Fatal("expected status dimension to be captured")
	}
	if _, present := dimensions["ignored.empty"]; present {
		t.Fatal("blank dimension values must be dropped")
	}
	if measurements["result.count"] != 7 {
		t.Fatalf("result.count = %d, want 7", measurements["result.count"])
	}

	// Snapshot must be a copy: later mutations should not leak into it.
	collector.Dimension("late.add", "x")
	if _, present := dimensions["late.add"]; present {
		t.Fatal("snapshot should not observe post-snapshot mutations")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestWideEventInterceptorEmitsForUninstrumentedRPC drives a real request
// through the handler stack for CheckHealth, which never emitted a wide event
// in the per-handler model, and asserts the interceptor now produces one
// canonical event.
func TestWideEventInterceptorEmitsForUninstrumentedRPC(t *testing.T) {
	sink := &syncBuffer{}
	restore := telemetry.SetOutput(sink)
	defer restore()

	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/aperio.v1.AperioService/CheckHealth",
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call CheckHealth: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CheckHealth status = %d, want 200", resp.StatusCode)
	}

	var event map[string]any
	for _, line := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
		if line == "" {
			continue
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("emitted telemetry was not valid JSON: %v (line=%q)", err, line)
		}
		if decoded["rpc.method"] == "CheckHealth" {
			event = decoded
			break
		}
	}
	if event == nil {
		t.Fatalf("expected a wide event for CheckHealth, got: %q", sink.String())
	}
	if event["kind"] != "wide_event" {
		t.Errorf("kind = %v, want wide_event", event["kind"])
	}
	if event["event_name"] != "aperio.connect_rpc" {
		t.Errorf("event_name = %v, want aperio.connect_rpc", event["event_name"])
	}
	if event["unit_of_work"] != "connect_rpc" {
		t.Errorf("unit_of_work = %v, want connect_rpc", event["unit_of_work"])
	}
	if event["status"] != "success" {
		t.Errorf("status = %v, want success", event["status"])
	}
	if event["http.route"] != "/aperio.v1.AperioService/CheckHealth" {
		t.Errorf("http.route = %v, want the CheckHealth procedure", event["http.route"])
	}
	if _, ok := event["duration_ms"]; !ok {
		t.Error("expected duration_ms measurement on the wide event")
	}
}
