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

// TestCustomFindingDistinctSubjectsDoNotCollapse pins the dedupe-target
// contract: when a rule declares a SubjectField, two events with the same
// actor but distinct subject values must produce two findings (distinct
// DedupeTarget) instead of overwriting one row via ON CONFLICT
// (organization_id, dedupe_key).
func TestCustomFindingDistinctSubjectsDoNotCollapse(t *testing.T) {
	rule := CustomRule{
		ID:           "r1",
		Name:         "External share alert",
		Severity:     "HIGH",
		EventType:    "EXTERNAL_SHARING_ENABLED",
		SubjectField: "payload.parameters.target",
		Predicate:    mustPredicate(t, `{}`),
		Enabled:      true,
	}
	rules := []CustomRule{rule}
	a := EvaluateCustomRules(JobPayload{
		EventType: "EXTERNAL_SHARING_ENABLED",
		Actor:     "alice@x.com",
		Payload:   map[string]any{"parameters": map[string]any{"target": "doc-a"}},
	}, rules)
	b := EvaluateCustomRules(JobPayload{
		EventType: "EXTERNAL_SHARING_ENABLED",
		Actor:     "alice@x.com",
		Payload:   map[string]any{"parameters": map[string]any{"target": "doc-b"}},
	}, rules)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("each event should produce one finding, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeTarget == b[0].DedupeTarget {
		t.Fatalf("distinct subjects must produce distinct dedupe targets, got %q == %q", a[0].DedupeTarget, b[0].DedupeTarget)
	}
	if a[0].DedupeTarget != "doc-a" || b[0].DedupeTarget != "doc-b" {
		t.Fatalf("dedupe target should reflect resolved SubjectField: got %q / %q", a[0].DedupeTarget, b[0].DedupeTarget)
	}
	if a[0].Target != "doc-a" {
		t.Fatalf("display target should reflect SubjectField: got %q", a[0].Target)
	}
}

// TestCustomFindingWithoutSubjectFieldKeepsActorDedupe pins the safe
// default for legacy rules: when SubjectField is empty, behavior matches
// the prior actor-keyed dedupe so an unmigrated rule does not change
// semantics.
func TestCustomFindingWithoutSubjectFieldKeepsActorDedupe(t *testing.T) {
	rule := CustomRule{ID: "r1", EventType: "X", Severity: "HIGH", Predicate: mustPredicate(t, `{}`), Enabled: true}
	got := EvaluateCustomRules(JobPayload{EventType: "X", Actor: "alice@x.com"}, []CustomRule{rule})
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].DedupeTarget != "" {
		t.Fatalf("legacy rule without SubjectField must leave DedupeTarget unset so DedupeKey falls back to Target, got %q", got[0].DedupeTarget)
	}
	if got[0].Target != "alice@x.com" {
		t.Fatalf("legacy rule should use actor as Target, got %q", got[0].Target)
	}
}

// TestEvaluateCustomRulesNotEqualsRequiresFieldPresent pins the fix for
// the spurious-finding bug: an operator rule that compares a field with
// not_equals must NOT fire on events that simply omit the referenced
// field. Otherwise "not equal to private" silently degenerates to
// "missing OR not private", flooding dashboards with false positives.
func TestEvaluateCustomRulesNotEqualsRequiresFieldPresent(t *testing.T) {
	rule := CustomRule{
		ID:        "r1",
		EventType: "X",
		Severity:  "HIGH",
		Predicate: mustPredicate(t, `{"field":"payload.parameters.visibility","op":"not_equals","value":"private"}`),
		Enabled:   true,
	}
	// Field absent: must NOT fire.
	got := EvaluateCustomRules(JobPayload{EventType: "X", Payload: map[string]any{}}, []CustomRule{rule})
	if len(got) != 0 {
		t.Fatalf("not_equals must not fire when the field is absent, got %d findings", len(got))
	}
	// Field present and matching: must NOT fire.
	got = EvaluateCustomRules(JobPayload{EventType: "X", Payload: map[string]any{"parameters": map[string]any{"visibility": "private"}}}, []CustomRule{rule})
	if len(got) != 0 {
		t.Fatalf("not_equals must not fire when present-and-equal, got %d findings", len(got))
	}
	// Field present and differing: must fire.
	got = EvaluateCustomRules(JobPayload{EventType: "X", Payload: map[string]any{"parameters": map[string]any{"visibility": "public"}}}, []CustomRule{rule})
	if len(got) != 1 {
		t.Fatalf("not_equals must fire when present-and-differing, got %d findings", len(got))
	}
}

// TestValidatePredicateRejectsMalformedShapes pins the gate that prevents
// the bootstrap API from persisting a 200 for a predicate the evaluator
// can never execute. Without this check json.Marshal accepts any JSON
// value (scalar, array, object), the row lands in the DB, and the
// evaluator's Unmarshal-into-predicateNode failure is silently swallowed
// as a clean skip — the operator sees a phantom rule in the UI that
// never matches anything.
func TestValidatePredicateRejectsMalformedShapes(t *testing.T) {
	bad := map[string]string{
		"scalar number":    `5`,
		"scalar string":    `"foo"`,
		"array":            `["x"]`,
		"unknown op":       `{"op":"regex","field":"actor","value":".*"}`,
		"missing op":       `{"field":"actor","value":"x"}`,
		"missing field":    `{"op":"equals","value":"x"}`,
		"missing value":    `{"op":"equals","field":"actor"}`,
		"unknown key":      `{"op":"equals","field":"actor","value":"x","extra":1}`,
		"empty and":        `{"op":"and","predicates":[]}`,
		"nested bad child": `{"op":"or","predicates":[{"op":"equals","field":"actor","value":"x"},{"op":"regex","field":"a","value":"b"}]}`,
	}
	for name, body := range bad {
		if err := ValidatePredicate([]byte(body)); err == nil {
			t.Errorf("%s: expected ValidatePredicate to reject %s", name, body)
		}
	}
}

func TestValidatePredicateAcceptsValidShapes(t *testing.T) {
	good := []string{
		``,
		`{}`,
		`null`,
		`{"op":"equals","field":"actor","value":"x@y.com"}`,
		`{"op":"not_equals","field":"payload.visibility","value":"private"}`,
		`{"op":"contains","field":"payload.target_domain","value":"@vendor."}`,
		`{"op":"in","field":"payload.scope","value":["a","b"]}`,
		`{"op":"exists","field":"payload.token"}`,
		`{"op":"and","predicates":[{"op":"equals","field":"actor","value":"x"},{"op":"or","predicates":[{"op":"contains","field":"a","value":"b"},{"op":"exists","field":"c"}]}]}`,
	}
	for _, body := range good {
		if err := ValidatePredicate([]byte(body)); err != nil {
			t.Errorf("ValidatePredicate rejected valid predicate %s: %v", body, err)
		}
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
