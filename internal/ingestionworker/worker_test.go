package ingestionworker

import "testing"

func TestEvaluateGitHubPublicRepository(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Payload: map[string]any{
			"repository": map[string]any{
				"full_name":  "writer/aperio",
				"visibility": "public",
			},
		},
	}
	findings := Evaluate(payload, nil)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].RuleID != "github.public_repository_created" {
		t.Fatalf("rule id = %s", findings[0].RuleID)
	}
	if findings[0].Target != "writer/aperio" {
		t.Fatalf("target = %s", findings[0].Target)
	}
	if findings[0].Severity != "CRITICAL" || findings[0].RiskScore != 95 {
		t.Fatalf("unexpected severity/risk: %#v", findings[0])
	}
}

func TestDedupeKeyIsStableAcrossObservations(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
	}
	finding := Finding{RuleID: "github.public_repository_created", Target: "writer/aperio"}
	first := DedupeKey(payload, finding)
	second := DedupeKey(payload, finding)
	if first == "" || first != second {
		t.Fatalf("dedupe key not stable: %q %q", first, second)
	}
	payload.EventType = "OTHER_EVENT"
	if DedupeKey(payload, finding) != first {
		t.Fatal("dedupe key should exclude event type so repeated observations update the same finding")
	}
}
