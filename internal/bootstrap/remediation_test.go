package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExecuteRemediationOktaSuspend(t *testing.T) {
	app := &App{}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "OKTA",
		Action:            "okta.suspend_user",
		ExternalAccountID: "acme.okta.com",
		TargetIdentifier:  "user@example.com",
	})
	if !result.Success {
		t.Fatal("expected okta.suspend_user to succeed")
	}
	if !strings.HasPrefix(result.ProviderRequestID, "okta_") {
		t.Fatalf("unexpected provider request id: %s", result.ProviderRequestID)
	}
	if len(result.Effects) != 3 {
		t.Fatalf("expected 3 effects, got %d", len(result.Effects))
	}
	if !strings.Contains(result.Effects[0], "user@example.com") {
		t.Fatalf("expected target in effect: %s", result.Effects[0])
	}
}

func TestExecuteRemediationSlackRevokeCallsAdminAppsUninstall(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if r.URL.Path != "/admin.apps.uninstall" {
			t.Fatalf("path = %s, want /admin.apps.uninstall", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer xoxp-remediation" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("app_id"); got != "A123" {
			t.Fatalf("app_id = %q", got)
		}
		if got := r.Form.Get("team_id"); got != "T123" {
			t.Fatalf("team_id = %q", got)
		}
		w.Header().Set("X-Slack-Req-Id", "slack-req-123")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	app := &App{remediationHTTPClient: server.Client(), slackAPIBaseURL: server.URL}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "SLACK",
		Action:            "slack.revoke_app_install",
		ExternalAccountID: "T123",
		TargetIdentifier:  "A123",
		IntegrationToken:  "xoxp-remediation",
	})
	if !result.Success {
		t.Fatalf("expected slack.revoke_app_install to succeed: %+v", result)
	}
	if called.Load() != 1 {
		t.Fatalf("expected exactly one Slack request, got %d", called.Load())
	}
	if result.ProviderRequestID != "slack-req-123" {
		t.Fatalf("provider request id = %s", result.ProviderRequestID)
	}
	if result.Effects[0] != "admin.apps.uninstall" {
		t.Fatalf("unexpected first effect: %s", result.Effects[0])
	}
}

func TestExecuteRemediationSlackRevokeProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Slack-Req-Id", "slack-req-failed")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing_scope"})
	}))
	defer server.Close()

	app := &App{remediationHTTPClient: server.Client(), slackAPIBaseURL: server.URL}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "SLACK",
		Action:            "slack.revoke_app_install",
		ExternalAccountID: "T123",
		TargetIdentifier:  "A123",
		IntegrationToken:  "xoxp-remediation",
	})
	if result.Success {
		t.Fatal("expected Slack provider failure to fail remediation")
	}
	if result.ProviderRequestID != "slack-req-failed" {
		t.Fatalf("provider request id = %s", result.ProviderRequestID)
	}
	if !strings.Contains(result.Message, "missing_scope") {
		t.Fatalf("expected Slack error in message, got %q", result.Message)
	}
	if len(result.Effects) != 0 {
		t.Fatalf("expected no effects, got %d", len(result.Effects))
	}
}

func TestExecuteRemediationSlackRevokeRequiresTargetBeforeNetwork(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called.Add(1)
	}))
	defer server.Close()

	app := &App{remediationHTTPClient: server.Client(), slackAPIBaseURL: server.URL}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "SLACK",
		Action:            "slack.revoke_app_install",
		ExternalAccountID: "T123",
		IntegrationToken:  "xoxp-remediation",
	})
	if result.Success {
		t.Fatal("expected missing Slack app id to fail")
	}
	if called.Load() != 0 {
		t.Fatalf("expected no provider request, got %d", called.Load())
	}
	if !strings.Contains(result.Message, "app id is required") {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestExecuteRemediationNotImplemented(t *testing.T) {
	app := &App{}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "MICROSOFT_365",
		Action:            "ms365.revoke_sessions",
		ExternalAccountID: "acme.onmicrosoft.com",
		TargetIdentifier:  "user@example.com",
	})
	if result.Success {
		t.Fatal("expected ms365.revoke_sessions to be unimplemented")
	}
	if len(result.Effects) != 0 {
		t.Fatalf("expected no effects, got %d", len(result.Effects))
	}
	if !strings.Contains(result.Message, "not yet implemented") {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestExecuteRemediationUnknownAction(t *testing.T) {
	app := &App{}
	result := app.executeRemediation(context.Background(), remediationRequest{
		Provider:          "OKTA",
		Action:            "okta.unknown_action",
		ExternalAccountID: "acme.okta.com",
		TargetIdentifier:  "user@example.com",
	})
	if result.Success {
		t.Fatal("expected unknown action to fail")
	}
	if !strings.HasPrefix(result.ProviderRequestID, "unknown_") {
		t.Fatalf("unexpected provider request id: %s", result.ProviderRequestID)
	}
}

func TestConnectorHasRemediationAction(t *testing.T) {
	connector := findConnectorDefinition("OKTA")
	if connector == nil {
		t.Fatal("expected OKTA connector definition")
	}
	if !connectorHasRemediationAction(connector, "okta.suspend_user") {
		t.Fatal("expected okta.suspend_user to be defined for OKTA")
	}
	if connectorHasRemediationAction(connector, "slack.revoke_app_install") {
		t.Fatal("did not expect slack action on OKTA connector")
	}
}
