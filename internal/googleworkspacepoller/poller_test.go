package googleworkspacepoller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMapEventTypeDriveExternalSharing(t *testing.T) {
	got := MapEventType("drive", "change_user_access", []reportsParameter{
		{Name: "visibility", Value: "shared_externally"},
	})
	if got != "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("want EXTERNAL_SHARING_ENABLED, got %s", got)
	}
}

func TestMapEventTypeDriveInternalShareUnmapped(t *testing.T) {
	got := MapEventType("drive", "change_user_access", []reportsParameter{
		{Name: "visibility", Value: "private"},
	})
	if got == "EXTERNAL_SHARING_ENABLED" {
		t.Fatalf("private share must not map to EXTERNAL_SHARING_ENABLED")
	}
}

func TestMapEventTypeAdminSuperAdminGrant(t *testing.T) {
	got := MapEventType("admin", "assign_role", []reportsParameter{
		{Name: "ROLE_NAME", Value: "_SEED_ADMIN_ROLE"},
	})
	if got != "SUPER_ADMIN_GRANTED" {
		t.Fatalf("want SUPER_ADMIN_GRANTED, got %s", got)
	}
}

func TestMapEventTypeAdminRoleGrantFallback(t *testing.T) {
	got := MapEventType("admin", "assign_role", []reportsParameter{
		{Name: "ROLE_NAME", Value: "Help Desk Admin"},
	})
	if got != "ADMIN_ROLE_GRANTED" {
		t.Fatalf("want ADMIN_ROLE_GRANTED, got %s", got)
	}
}

func TestMapEventTypeTokenAuthorize(t *testing.T) {
	got := MapEventType("token", "authorize", nil)
	if got != "RISKY_OAUTH_GRANT" {
		t.Fatalf("want RISKY_OAUTH_GRANT, got %s", got)
	}
}

func TestMapEventTypeUnknownPassthrough(t *testing.T) {
	got := MapEventType("drive", "some_new_event", nil)
	if got != "SOME_NEW_EVENT" {
		t.Fatalf("expected uppercase passthrough, got %s", got)
	}
}

func TestCursorRowIsStrictlyAfter(t *testing.T) {
	c := cursorRow{LastEventTime: time.Unix(1000, 0).UTC(), LastUniqueQualifier: "B"}
	if c.isStrictlyAfter(time.Unix(900, 0).UTC(), "Z") {
		t.Fatal("earlier event misclassified as newer")
	}
	if !c.isStrictlyAfter(time.Unix(1100, 0).UTC(), "A") {
		t.Fatal("later event misclassified as not-newer")
	}
	if !c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "C") {
		t.Fatal("same time, higher qualifier must be newer")
	}
	if c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "A") {
		t.Fatal("same time, lower qualifier must NOT be newer")
	}
	if c.isStrictlyAfter(time.Unix(1000, 0).UTC(), "B") {
		t.Fatal("identical cursor must NOT be newer")
	}
	empty := cursorRow{}
	if !empty.isStrictlyAfter(time.Unix(0, 0).UTC(), "") {
		t.Fatal("zero cursor must accept anything")
	}
}

func TestBuildJobPayloadFlattensParameters(t *testing.T) {
	bv := true
	payload := buildJobPayload("drive", reportsActivity{
		EventTime:       time.Unix(1700000000, 0).UTC(),
		UniqueQualifier: "abc",
		Actor:           reportsActor{Email: "alice@example.com"},
	}, reportsEvent{
		Name: "change_user_access",
		Parameters: []reportsParameter{
			{Name: "doc_title", Value: "Board Deck"},
			{Name: "doc_id", Value: "1xyz"},
			{Name: "visibility", Value: "shared_externally"},
			{Name: "owner_is_team_drive", BoolValue: &bv},
			{Name: "shared_with", MultiValue: []string{"bob@partner.com"}},
		},
	})
	params, ok := payload["parameters"].(map[string]any)
	if !ok {
		t.Fatal("parameters missing or wrong type")
	}
	if params["doc_title"] != "Board Deck" {
		t.Fatalf("doc_title not flattened: %v", params)
	}
	if params["owner_is_team_drive"] != true {
		t.Fatalf("bool param not preserved: %v", params)
	}
	if mv, ok := params["shared_with"].([]string); !ok || len(mv) != 1 || mv[0] != "bob@partner.com" {
		t.Fatalf("multi value not preserved: %v", params)
	}
	if payload["sourceEventId"] != "abc" {
		t.Fatalf("sourceEventId not derived from uniqueQualifier: %v", payload["sourceEventId"])
	}
	if payload["ownerDomain"] != "example.com" {
		t.Fatalf("ownerDomain not derived: %v", payload["ownerDomain"])
	}
	resource, ok := payload["resource"].(map[string]any)
	if !ok || resource["name"] != "Board Deck" || resource["id"] != "1xyz" {
		t.Fatalf("resource not derived: %v", payload["resource"])
	}
}

type fakeResolver struct{}

func (fakeResolver) ResolveGoogleOAuthClient(_ context.Context, _ string) (OAuthConfig, bool) {
	return OAuthConfig{ClientID: "cid", ClientSecret: "csecret"}, true
}

// TestExchangeRefreshToken pins the token-exchange wire shape so a future
// regression that drops grant_type or client_secret is caught without
// hitting real Google.
func TestExchangeRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		for _, f := range []string{"client_id", "client_secret", "refresh_token", "grant_type"} {
			if r.PostForm.Get(f) == "" {
				t.Errorf("missing form field %s", f)
			}
		}
		if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type=%s, want refresh_token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.fake","expires_in":3600}`))
	}))
	defer server.Close()

	p := New(nil, fakeResolver{})
	p.httpClient = server.Client()
	// Override the token URL for the test by wrapping http.RoundTripper.
	p.httpClient.Transport = rewriteHostRoundTripper{base: p.httpClient.Transport, target: server.URL}
	access, err := p.exchangeRefreshToken(context.Background(), OAuthConfig{ClientID: "cid", ClientSecret: "csecret"}, "1//refresh")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if access != "ya29.fake" {
		t.Fatalf("unexpected access token: %s", access)
	}
}

type rewriteHostRoundTripper struct {
	base   http.RoundTripper
	target string
}

func (r rewriteHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Strip the original host and re-point at our httptest server so we don't
	// have to monkey-patch the constants for one test.
	prefix := req.URL.Scheme + "://" + req.URL.Host
	_ = prefix
	idx := strings.Index(r.target, "://")
	scheme := "http"
	host := r.target
	if idx >= 0 {
		scheme = r.target[:idx]
		host = r.target[idx+3:]
	}
	req.URL.Scheme = scheme
	req.URL.Host = host
	req.URL.Path = "/"
	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
