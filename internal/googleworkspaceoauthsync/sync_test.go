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
