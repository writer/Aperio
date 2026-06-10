package googleworkspaceoauthsync

import (
	"strings"
	"testing"
)

func TestParseTokenPreservesScopes(t *testing.T) {
	got := parseToken(googleToken{
		ClientID:    "  vendor-app  ",
		DisplayText: " Vendor Analytics ",
		Scopes:      []string{"drive.readonly", "gmail.metadata"},
		Anonymous:   false,
		NativeApp:   true,
	})
	if got.ClientID != "vendor-app" {
		t.Fatalf("ClientID trim: got %q", got.ClientID)
	}
	if got.Label != "Vendor Analytics" {
		t.Fatalf("Label trim: got %q", got.Label)
	}
	if got.NativeApp != true || got.Anonymous != false {
		t.Fatalf("flag passthrough wrong: %+v", got)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("Scopes len: got %d", len(got.Scopes))
	}
}

func TestDisplayNameFallsBackToClientID(t *testing.T) {
	if got := (parsedToken{ClientID: "abc.apps", Label: ""}).DisplayName(); got != "abc.apps" {
		t.Fatalf("DisplayName fallback: got %q", got)
	}
	if got := (parsedToken{ClientID: "abc", Label: "Acme"}).DisplayName(); got != "Acme" {
		t.Fatalf("DisplayName label: got %q", got)
	}
}

func TestSummaryTruncatesLongScopeLists(t *testing.T) {
	scopes := []string{"a", "b", "c", "d", "e"}
	got := (parsedToken{Scopes: scopes}).Summary()
	if !strings.Contains(got, "a, b, c") {
		t.Fatalf("Summary should include first 3 scopes: got %q", got)
	}
	if !strings.Contains(got, "+2 more") {
		t.Fatalf("Summary should report remainder: got %q", got)
	}
}

func TestSummaryHandlesEmptyScopes(t *testing.T) {
	if got := (parsedToken{}).Summary(); got != "Third-party OAuth app" {
		t.Fatalf("empty-scope summary: got %q", got)
	}
}

// TestShortHashDistinguishesDistinctUserKeys pins the collision-resistance
// property the grant PK relies on. Two identities that share an empty
// external_id must derive distinct PK suffixes from their email userKey so
// upsertOauthGrant does not abort the sweep with a duplicate-key error on
// the second user under the same (integration, client) pair.
func TestShortHashDistinguishesDistinctUserKeys(t *testing.T) {
	a := shortHash("alice@example.test")
	b := shortHash("bob@example.test")
	if a == b {
		t.Fatalf("distinct emails must hash to distinct PK suffixes: %q == %q", a, b)
	}
	if shortHash("alice@example.test") != a {
		t.Fatal("shortHash must be deterministic")
	}
	if shortHash("") == shortHash("alice@example.test") {
		t.Fatal("empty userKey must not collide with a real one")
	}
	if len(a) != 12 {
		t.Fatalf("shortHash should produce a 12-char fragment, got %d", len(a))
	}
}

// TestGrantPKAndArbiterMoveTogether pins the invariant that the grant PK
// and the natural-key arbiter (user_email) move together so neither the
// recreate case (email reused, new external_id) nor the rename case
// (external_id stable, email changes) can wedge the sweep with an
// unabsorbable unique violation. The PK suffix must change iff the
// email-or-external-id key changes.
func TestGrantPKAndArbiterMoveTogether(t *testing.T) {
	pkFor := func(email, externalID string) string {
		key := email
		if key == "" {
			key = externalID
		}
		return shortHash(key)
	}
	// Recreate: same email, different external_id -> same PK -> arbiter
	// matches existing row, DO UPDATE absorbs.
	if pkFor("alice@example.test", "ext-old") != pkFor("alice@example.test", "ext-new") {
		t.Fatal("email-reuse / recreate must keep the PK stable so arbiter UPDATE absorbs the row")
	}
	// Rename: stable external_id, new email -> different PK -> fresh
	// INSERT (no PK collision), arbiter miss, new row.
	if pkFor("alice.old@example.test", "ext-1") == pkFor("alice.new@example.test", "ext-1") {
		t.Fatal("rename must produce a different PK so the fresh INSERT does not collide with the prior row")
	}
	// Empty-email fallback: still distinguishes two external_ids.
	if pkFor("", "ext-1") == pkFor("", "ext-2") {
		t.Fatal("empty-email fallback must distinguish distinct external_ids")
	}
}

func TestStringArrayLiteralEscapes(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "{}"},
		{[]string{}, "{}"},
		{[]string{"a", "b"}, `{"a","b"}`},
		{[]string{`with "quote"`}, `{"with \"quote\""}`},
		{[]string{`back\slash`}, `{"back\\slash"}`},
	}
	for _, c := range cases {
		if got := stringArrayLiteral(c.in); got != c.want {
			t.Errorf("stringArrayLiteral(%v)=%q want %q", c.in, got, c.want)
		}
	}
}
