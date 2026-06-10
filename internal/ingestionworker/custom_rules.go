package ingestionworker

import (
	"encoding/json"
	"strings"
)

// CustomRule is one user-authored rule from custom_finding_rules. The
// predicate is a small expression tree:
//
//	{
//	  "op": "and" | "or",
//	  "predicates": [
//	    { "field": "actor", "op": "equals", "value": "x@y.com" },
//	    {
//	      "op": "or",
//	      "predicates": [
//	        { "field": "payload.parameters.target_domain", "op": "contains", "value": "@vendor." },
//	        { "field": "payload.parameters.visibility", "op": "in", "value": ["anyone","anyone_with_link"] }
//	      ]
//	    }
//	  ]
//	}
//
// A leaf predicate is `{field, op, value}`. A branch predicate is
// `{op, predicates}`. The DSL is intentionally narrow — five leaf
// operators (`equals`, `not_equals`, `contains`, `exists`, `in`) over
// dot-pathed payload fields — so a JSON-only authoring UI can produce
// rules without exposing the full power of arbitrary code.
type CustomRule struct {
	ID             string
	OrganizationID string
	IntegrationID  string
	Name           string
	Severity       string
	EventType      string
	// SubjectField is a dot-pathed reference (see resolveField) that the
	// evaluator uses as both Finding.Target and Finding.DedupeTarget. When
	// non-empty it lets one rule produce per-subject findings (e.g. one
	// finding per externally-shared file) instead of collapsing every event
	// for the same actor into a single security_findings row via the
	// dedupe_key UPSERT. Empty preserves the actor-keyed default.
	SubjectField string
	Predicate    json.RawMessage
	Enabled      bool
}

// EvaluateCustomRules runs every enabled CustomRule against the payload
// and returns one Finding per match. Mismatched event_type short-circuits
// before predicate evaluation so a tenant with hundreds of custom rules
// pays only one string compare per non-matching rule.
func EvaluateCustomRules(payload JobPayload, rules []CustomRule) []Finding {
	out := make([]Finding, 0, 2)
	normalized := normalizeEventType(payload.EventType)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.EventType != "" && normalizeEventType(rule.EventType) != normalized {
			continue
		}
		ok, err := evalPredicate(rule.Predicate, payload)
		if err != nil || !ok {
			continue
		}
		out = append(out, customFinding(rule, payload))
	}
	return out
}

func customFinding(rule CustomRule, payload JobPayload) Finding {
	severity := strings.ToUpper(strings.TrimSpace(rule.Severity))
	if severity == "" {
		severity = "MEDIUM"
	}
	actor := payload.Actor
	if actor == "" {
		actor = rule.Name
	}
	// Resolve the operator-declared subject from the payload. When set, it
	// becomes both the human-facing Target and the dedupe key suffix so two
	// distinct subjects under the same actor (e.g. the same user externally
	// sharing two files) produce two separate security_findings rows
	// instead of overwriting one another via ON CONFLICT (org, dedupe_key).
	subject := actor
	dedupe := ""
	if strings.TrimSpace(rule.SubjectField) != "" {
		if resolved := predicateString(resolveField(rule.SubjectField, payload)); resolved != "" {
			subject = resolved
			dedupe = resolved
		}
	}
	return Finding{
		RuleID:       "custom." + rule.ID,
		Title:        rule.Name,
		Description:  "Custom rule defined by operator on this integration.",
		Severity:     severity,
		RiskScore:    severityToRiskScore(severity),
		Target:       subject,
		DedupeTarget: dedupe,
		Evidence: map[string]any{
			"ruleId":       "custom." + rule.ID,
			"customRuleId": rule.ID,
			"target":       subject,
			"subject":      subject,
			"actor":        actor,
			"provider":     payload.Provider,
			"eventType":    payload.EventType,
		},
	}
}

func severityToRiskScore(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 70
	case "MEDIUM":
		return 50
	case "LOW":
		return 30
	default:
		return 50
	}
}

// evalPredicate is the recursive predicate evaluator. Returns ok=false +
// nil error for a clean non-match; the err return only surfaces a
// structurally invalid predicate (missing field, unknown op) so a
// malformed rule cannot silently swallow a match.
func evalPredicate(raw json.RawMessage, payload JobPayload) (bool, error) {
	if len(raw) == 0 || string(raw) == "{}" {
		// Empty predicate is treated as "always match for this event_type".
		// The event_type filter in EvaluateCustomRules has already narrowed
		// the candidate set, so an empty predicate is a useful sentinel for
		// "every event of this type is a finding."
		return true, nil
	}
	var node predicateNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, err
	}
	return evalNode(node, payload)
}

type predicateNode struct {
	Op         string          `json:"op,omitempty"`
	Predicates []predicateNode `json:"predicates,omitempty"`
	Field      string          `json:"field,omitempty"`
	Value      json.RawMessage `json:"value,omitempty"`
}

func evalNode(node predicateNode, payload JobPayload) (bool, error) {
	switch strings.ToLower(node.Op) {
	case "and":
		for _, child := range node.Predicates {
			ok, err := evalNode(child, payload)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case "or":
		for _, child := range node.Predicates {
			ok, err := evalNode(child, payload)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case "equals", "==":
		return leafEquals(node, payload, false), nil
	case "not_equals", "!=":
		// A naive `!leafEquals` fires on every event that simply omits
		// the field, since resolveField returns nil → "" → !equals(value)
		// → true. That turns "not equal to private" into "missing OR not
		// private" and generates spurious findings. Require the field to
		// be present so not_equals expresses "present and differing"; an
		// operator who wants "missing OR differing" can express it with
		// an explicit OR over `exists` and `not_equals`.
		if resolveField(node.Field, payload) == nil {
			return false, nil
		}
		return !leafEquals(node, payload, false), nil
	case "contains":
		return leafContains(node, payload), nil
	case "exists":
		return resolveField(node.Field, payload) != nil, nil
	case "in":
		return leafIn(node, payload), nil
	default:
		// Unknown op — treat as no-match. We intentionally do NOT return
		// an error so a tenant with one malformed rule does not poison the
		// worker; the rule simply never fires until the operator fixes it.
		return false, nil
	}
}

func leafEquals(node predicateNode, payload JobPayload, caseSensitive bool) bool {
	left := predicateString(resolveField(node.Field, payload))
	right := stringValueOfRaw(node.Value)
	if caseSensitive {
		return left == right
	}
	return strings.EqualFold(left, right)
}

func leafContains(node predicateNode, payload JobPayload) bool {
	left := predicateString(resolveField(node.Field, payload))
	right := stringValueOfRaw(node.Value)
	if right == "" {
		return false
	}
	return strings.Contains(strings.ToLower(left), strings.ToLower(right))
}

func leafIn(node predicateNode, payload JobPayload) bool {
	left := predicateString(resolveField(node.Field, payload))
	var arr []json.RawMessage
	if err := json.Unmarshal(node.Value, &arr); err != nil {
		return false
	}
	for _, v := range arr {
		if strings.EqualFold(left, stringValueOfRaw(v)) {
			return true
		}
	}
	return false
}

// resolveField walks a dot-pathed field reference. Top-level fields
// `actor`, `eventType`, `source`, `integrationId`, `organizationId`
// resolve to the JobPayload column; `payload.x.y` walks into the
// JSONB payload map.
func resolveField(field string, payload JobPayload) any {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}
	switch field {
	case "actor":
		return payload.Actor
	case "eventType":
		return payload.EventType
	case "source":
		return payload.Source
	case "integrationId":
		return payload.IntegrationID
	case "organizationId":
		return payload.OrganizationID
	}
	if !strings.HasPrefix(field, "payload.") {
		// Allow bare "key" to mean payload.key for ergonomic rule writing.
		return walkMap(payload.Payload, strings.Split(field, "."))
	}
	return walkMap(payload.Payload, strings.Split(field[len("payload."):], "."))
}

func walkMap(m map[string]any, parts []string) any {
	if m == nil || len(parts) == 0 {
		return nil
	}
	var cur any = m
	for _, part := range parts {
		switch typed := cur.(type) {
		case map[string]any:
			cur = typed[part]
		default:
			return nil
		}
	}
	return cur
}

func predicateString(v any) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return jsonNumberString(typed)
	}
	if b, err := json.Marshal(v); err == nil {
		return strings.Trim(string(b), `"`)
	}
	return ""
}

func stringValueOfRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fall through for numbers/booleans rendered as JSON literals.
	return strings.Trim(string(raw), `"`)
}

func jsonNumberString(f float64) string {
	// Integers should render without a trailing .0 so a string match against
	// a user-typed "5" succeeds.
	if f == float64(int64(f)) {
		return strconvI64(int64(f))
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func strconvI64(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [24]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = digits[n%10]
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
