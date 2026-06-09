package ingestionworker

import (
	"encoding/json"
	"testing"
)

func mustPredicate(t *testing.T, s string) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatalf("invalid predicate JSON: %v", err)
	}
	return raw
}

func TestEvaluateCustomRulesEmptyPredicateMatchesByEventType(t *testing.T) {
	rules := []CustomRule{{
		ID:        "r1",
		Name:      "All external sharing",
		Severity:  "HIGH",
		EventType: "EXTERNAL_SHARING_ENABLED",
		Predicate: mustPredicate(t, `{}`),
		Enabled:   true,
	}}
	got := EvaluateCustomRules(JobPayload{EventType: "EXTERNAL_SHARING_ENABLED", Actor: "alice@x.com"}, rules)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "HIGH" {
		t.Fatalf("severity passthrough wrong: %s", got[0].Severity)
	}
	if got[0].RuleID != "custom.r1" {
		t.Fatalf("rule id should be custom.<id>: %s", got[0].RuleID)
	}
}

func TestEvaluateCustomRulesDisabledRuleIsSkipped(t *testing.T) {
	rules := []CustomRule{{
		ID:        "r1",
		EventType: "X",
		Predicate: mustPredicate(t, `{}`),
		Enabled:   false,
	}}
	got := EvaluateCustomRules(JobPayload{EventType: "X"}, rules)
	if len(got) != 0 {
		t.Fatalf("disabled rule must not fire, got %d findings", len(got))
	}
}

func TestEvaluateCustomRulesAndOrPredicates(t *testing.T) {
	payload := JobPayload{
		EventType: "RISKY_OAUTH_GRANT",
		Actor:     "morgan.finance@acme.test",
		Payload: map[string]any{
			"parameters": map[string]any{
				"app_name":      "Vendor Analytics",
				"target_domain": "partner.com",
			},
		},
	}
	rules := []CustomRule{{
		ID:        "vendor_grant",
		Name:      "Vendor analytics OAuth grants from finance",
		Severity:  "HIGH",
		EventType: "RISKY_OAUTH_GRANT",
		Predicate: mustPredicate(t, `{
			"op":"and","predicates":[
				{"field":"actor","op":"contains","value":"@acme.test"},
				{"op":"or","predicates":[
					{"field":"payload.parameters.app_name","op":"equals","value":"Vendor Analytics"},
					{"field":"payload.parameters.target_domain","op":"in","value":["partner.com","contractor.com"]}
				]}
			]
		}`),
		Enabled: true,
	}}
	got := EvaluateCustomRules(payload, rules)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
}

func TestEvaluateCustomRulesExistsAndContains(t *testing.T) {
	payload := JobPayload{
		EventType: "X",
		Payload:   map[string]any{"parameters": map[string]any{"sensitive_flag": "true"}},
	}
	rules := []CustomRule{
		{ID: "r_exists", EventType: "X", Severity: "MEDIUM", Enabled: true, Predicate: mustPredicate(t, `{"field":"payload.parameters.sensitive_flag","op":"exists"}`)},
		{ID: "r_missing", EventType: "X", Severity: "MEDIUM", Enabled: true, Predicate: mustPredicate(t, `{"field":"payload.parameters.absent","op":"exists"}`)},
	}
	got := EvaluateCustomRules(payload, rules)
	if len(got) != 1 || got[0].RuleID != "custom.r_exists" {
		t.Fatalf("expected only r_exists to fire, got %+v", got)
	}
}

func TestEvaluateCustomRulesEventTypeMismatchShortCircuits(t *testing.T) {
	rules := []CustomRule{{
		ID:        "r1",
		EventType: "EXTERNAL_SHARING_ENABLED",
		Predicate: mustPredicate(t, `{}`),
		Enabled:   true,
	}}
	got := EvaluateCustomRules(JobPayload{EventType: "OTHER"}, rules)
	if len(got) != 0 {
		t.Fatalf("event-type mismatch must short-circuit: got %d findings", len(got))
	}
}

func TestEvaluateCustomRulesUnknownOpSilentlyDoesNotMatch(t *testing.T) {
	rules := []CustomRule{{
		ID:        "bad",
		EventType: "X",
		Predicate: mustPredicate(t, `{"op":"regex","field":"actor","value":"."}`),
		Enabled:   true,
	}}
	got := EvaluateCustomRules(JobPayload{EventType: "X", Actor: "anything"}, rules)
	if len(got) != 0 {
		t.Fatalf("unknown op must not match; a single malformed rule must not break the worker. got %d findings", len(got))
	}
}

func TestSeverityToRiskScoreUnknownDefaultsToMedium(t *testing.T) {
	if severityToRiskScore("CHARLIE") != 50 {
		t.Fatal("unknown severity must default to MEDIUM-equivalent score")
	}
	if severityToRiskScore("HIGH") != 70 {
		t.Fatal("HIGH score regressed")
	}
}
