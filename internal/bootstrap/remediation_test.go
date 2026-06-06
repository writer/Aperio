package bootstrap

import (
	"strings"
	"testing"
)

func TestExecuteRemediationOktaSuspend(t *testing.T) {
	result := executeRemediation("OKTA", "okta.suspend_user", "acme.okta.com", "user@example.com")
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

func TestExecuteRemediationSlackRevoke(t *testing.T) {
	result := executeRemediation("SLACK", "slack.revoke_app_install", "acme", "A123")
	if !result.Success {
		t.Fatal("expected slack.revoke_app_install to succeed")
	}
	if result.Effects[0] != "admin.apps.uninstall" {
		t.Fatalf("unexpected first effect: %s", result.Effects[0])
	}
}

func TestExecuteRemediationNotImplemented(t *testing.T) {
	result := executeRemediation("MICROSOFT_365", "ms365.revoke_sessions", "acme.onmicrosoft.com", "user@example.com")
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
	result := executeRemediation("OKTA", "okta.unknown_action", "acme.okta.com", "user@example.com")
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
