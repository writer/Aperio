package googleworkspacedirectorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMapIdentityActiveUserWithMfa pins the happy path: a recently-active
// internal user with 2-step enforced. This is the row shape every Security
// Graph and report KPI ultimately counts.
func TestMapIdentityActiveUserWithMfa(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	u := googleUser{
		ID:              "112233",
		PrimaryEmail:    "alice@company.com",
		Name:            googleUserName{FullName: "Alice Example"},
		IsEnforcedIn2Sv: true,
		LastLoginTime:   now.Add(-2 * 24 * time.Hour),
		CreationTime:    now.Add(-365 * 24 * time.Hour),
	}
	got := mapIdentity(u, "company.com", now)
	if got.ExternalID != "112233" || got.Email != "alice@company.com" || got.DisplayName != "Alice Example" {
		t.Fatalf("identity fields wrong: %+v", got)
	}
	if got.Status != "ACTIVE" {
		t.Fatalf("status: want ACTIVE got %s", got.Status)
	}
	if got.MfaEnabled == nil || !*got.MfaEnabled {
		t.Fatalf("mfa_enabled: want true got %v", got.MfaEnabled)
	}
	if got.IsPrivileged {
		t.Fatal("is_privileged: want false for non-admin")
	}
	if got.IsExternal {
		t.Fatal("is_external: want false for same-domain user")
	}
	if got.Role != "" {
		t.Fatalf("role: want empty for non-admin, got %q", got.Role)
	}
}

// TestMapStatusTransitions pins every branch of mapStatus. SUSPENDED beats
// DORMANT; DORMANT only fires when the lastLoginTime is older than 30d;
// brand-new accounts inside the dormancy window stay ACTIVE.
func TestMapStatusTransitions(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		u    googleUser
		want string
	}{
		{"suspended beats everything", googleUser{Suspended: true, LastLoginTime: now}, "SUSPENDED"},
		{"archived beats everything", googleUser{Archived: true, LastLoginTime: now}, "SUSPENDED"},
		{"never logged in but recently created", googleUser{CreationTime: now.Add(-7 * 24 * time.Hour)}, "ACTIVE"},
		{"never logged in and old account", googleUser{CreationTime: now.Add(-60 * 24 * time.Hour)}, "DORMANT"},
		{"recently logged in", googleUser{LastLoginTime: now.Add(-5 * 24 * time.Hour)}, "ACTIVE"},
		{"logged in 31d ago", googleUser{LastLoginTime: now.Add(-31 * 24 * time.Hour)}, "DORMANT"},
	}
	for _, tc := range cases {
		if got := mapStatus(tc.u, now); got != tc.want {
			t.Errorf("%s: want %s got %s", tc.name, tc.want, got)
		}
	}
}

// TestMapIdentityPrivilegedFlags pins that BOTH isAdmin and isDelegatedAdmin
// promote is_privileged so the "Admin & Privilege" section shows non-zero
// for any tenant that has at least one super or delegated admin.
func TestMapIdentityPrivilegedFlags(t *testing.T) {
	now := time.Now().UTC()
	if !mapIdentity(googleUser{ID: "1", IsAdmin: true}, "x.com", now).IsPrivileged {
		t.Fatal("super admin must be privileged")
	}
	if !mapIdentity(googleUser{ID: "2", IsDelegatedAdmin: true}, "x.com", now).IsPrivileged {
		t.Fatal("delegated admin must be privileged")
	}
	if mapIdentity(googleUser{ID: "3"}, "x.com", now).IsPrivileged {
		t.Fatal("regular user must not be privileged")
	}
	if got := mapIdentity(googleUser{ID: "4", IsAdmin: true}, "x.com", now).Role; got != "Super Admin" {
		t.Fatalf("role: want Super Admin got %q", got)
	}
	if got := mapIdentity(googleUser{ID: "5", IsDelegatedAdmin: true}, "x.com", now).Role; got != "Delegated Admin" {
		t.Fatalf("role: want Delegated Admin got %q", got)
	}
}

// TestIsExternalUserConservativeDefault locks in that an unknown
// tenantDomain reports is_external=false rather than flagging every user
// as external. The audit-log poller has the same conservative default;
// keeping them aligned prevents a class of cross-section reporting drift.
func TestIsExternalUserConservativeDefault(t *testing.T) {
	cases := []struct {
		email, tenant string
		want          bool
	}{
		{"alice@company.com", "company.com", false},
		{"alice@COMPANY.com", "company.com", false},
		{"alice@partner.com", "company.com", true},
		{"alice@company.com", "", false},
		{"", "company.com", false},
		{"bogus", "company.com", false},
		{"alice@", "company.com", false},
	}
	for _, tc := range cases {
		if got := isExternalUser(tc.email, tc.tenant); got != tc.want {
			t.Errorf("isExternalUser(%q,%q)=%v want %v", tc.email, tc.tenant, got, tc.want)
		}
	}
}

// TestMapIdentityMfaFlags pins the two paths to MFA-enabled: enrolled
// voluntarily, or enforced by admin policy. Either signal is enough.
func TestMapIdentityMfaFlags(t *testing.T) {
	now := time.Now().UTC()
	if got := mapIdentity(googleUser{ID: "1", IsEnrolledIn2Sv: true}, "x.com", now); !*got.MfaEnabled {
		t.Fatal("enrolled-only user must report mfa_enabled=true")
	}
	if got := mapIdentity(googleUser{ID: "2", IsEnforcedIn2Sv: true}, "x.com", now); !*got.MfaEnabled {
		t.Fatal("enforced-only user must report mfa_enabled=true")
	}
	if got := mapIdentity(googleUser{ID: "3"}, "x.com", now); *got.MfaEnabled {
		t.Fatal("user with neither enforced nor enrolled must report mfa_enabled=false")
	}
}

// TestListUsersPaginates exercises the page-walk happy path against a
// fake Directory API. This is the only place we can prove the maxResults
// + pageToken plumbing actually advances; the alternative (production-only
// observation) hides off-by-one bugs that silently drop the last page.
func TestListUsersPaginates(t *testing.T) {
	pages := [][]googleUser{
		{{ID: "1", PrimaryEmail: "a@x.com"}, {ID: "2", PrimaryEmail: "b@x.com"}},
		{{ID: "3", PrimaryEmail: "c@x.com"}},
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "customer=my_customer") {
			t.Errorf("expected customer=my_customer in query, got %q", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.RawQuery, "projection=full") {
			t.Errorf("expected projection=full in query, got %q", r.URL.RawQuery)
		}
		resp := googleUsersResponse{Users: pages[calls]}
		if calls < len(pages)-1 {
			resp.NextPageToken = "next"
		}
		calls++
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	s := New(nil, nil).WithHTTPClient(srv.Client())
	// Point the directory URL at the test server by overriding the
	// underlying transport's RoundTripper through a custom http.Client.
	// Simplest path: rewrite directoryUsersURL via a tiny client wrapper.
	s.httpClient = &http.Client{Transport: rewriteHost{base: srv.URL, inner: srv.Client().Transport}}
	got, err := s.listUsers(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("listUsers error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 users across 2 pages, got %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("want 2 page calls, got %d", calls)
	}
}

func TestListUsersPageCapReturnsError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(googleUsersResponse{
			Users:         []googleUser{{ID: "user-" + itoa(calls), PrimaryEmail: "user@example.com"}},
			NextPageToken: "more",
		})
	}))
	t.Cleanup(srv.Close)
	s := New(nil, nil).WithMaxPages(2)
	s.httpClient = &http.Client{Transport: rewriteHost{base: srv.URL, inner: srv.Client().Transport}}

	got, err := s.listUsers(context.Background(), "access-token")
	if err == nil {
		t.Fatal("expected page cap error")
	}
	if got != nil {
		t.Fatalf("page cap must not return a partial clean user list, got %d users", len(got))
	}
	if !strings.Contains(err.Error(), "page cap") {
		t.Fatalf("expected page cap error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("want exactly 2 capped page calls, got %d", calls)
	}
}

// rewriteHost is a minimal RoundTripper that swaps any incoming request's
// scheme + host for the test server's. Lets the test exercise the real
// listUsers() URL construction (query params, headers) without mutating
// the production directoryUsersURL constant.
type rewriteHost struct {
	base  string
	inner http.RoundTripper
}

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	parsed, _ := req.URL.Parse(r.base)
	clone.URL.Scheme = parsed.Scheme
	clone.URL.Host = parsed.Host
	clone.URL.Path = parsed.Path + req.URL.Path[len("/admin/directory/v1/users"):]
	clone.Host = parsed.Host
	if r.inner == nil {
		return http.DefaultTransport.RoundTrip(clone)
	}
	return r.inner.RoundTrip(clone)
}
