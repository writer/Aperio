package ingestionworker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRuleCatalogMatchesEvaluators pins the cross-file contract that the
// UI-facing RuleCatalog stays in lockstep with the Evaluate() switch in
// worker.go. Drift would either hide a real rule from the toggle UI (so
// users see findings they can't disable) or surface a phantom rule (so
// users disable something that never produces findings). Both regressions
// caused real ops noise in similar systems we've seen.
//
// The test scans worker.go for every `disabled["..."]` lookup inside
// Evaluate and asserts each one has a matching RuleCatalog entry, and
// vice versa.
func TestRuleCatalogMatchesEvaluators(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("worker.go"))
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	re := regexp.MustCompile(`disabled\["([a-z0-9_.]+)"\]`)
	gateMatches := re.FindAllStringSubmatch(string(source), -1)
	seen := map[string]bool{}
	for _, m := range gateMatches {
		seen[m[1]] = true
	}
	for ruleID := range seen {
		found := false
		for _, entry := range RuleCatalog {
			if entry.ID == ruleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("worker.go gates rule %q via disabled[] but RuleCatalog has no entry (UI will hide a real rule)", ruleID)
		}
	}
	for _, entry := range RuleCatalog {
		if !seen[entry.ID] {
			t.Errorf("RuleCatalog declares %q but worker.go never gates it (UI lists a phantom toggle)", entry.ID)
		}
	}
}

// TestRuleCatalogProvidersAreKnown defends against a typo in Provider
// classifying a rule under a SaaS provider the connectors UI does not
// surface, which would orphan the toggle.
func TestRuleCatalogProvidersAreKnown(t *testing.T) {
	known := map[string]bool{"GITHUB": true, "SLACK": true, "OKTA": true, "GOOGLE_WORKSPACE": true}
	for _, entry := range RuleCatalog {
		if !known[entry.Provider] {
			t.Errorf("rule %q has unknown provider %q", entry.ID, entry.Provider)
		}
	}
}

// TestRuleCatalogForProviderFiltersDeterministically pins the helper used
// by the API so the UI shows a stable order.
func TestRuleCatalogForProviderFiltersDeterministically(t *testing.T) {
	got := RuleCatalogForProvider("GOOGLE_WORKSPACE")
	if len(got) < 6 {
		t.Fatalf("expected Google rules to be present, got %d", len(got))
	}
	for i := 0; i < len(got)-1; i++ {
		if got[i].Provider != "GOOGLE_WORKSPACE" {
			t.Fatalf("filter leaked non-Google rule at %d: %s", i, got[i].ID)
		}
	}
	// Sanity-check that the IDs follow the convention "<provider>.<slug>"
	// so the UI can group by prefix without an extra lookup table.
	for _, entry := range got {
		if !strings.HasPrefix(entry.ID, "google_workspace.") {
			t.Errorf("Google rule id should start with google_workspace.: %s", entry.ID)
		}
	}
}
