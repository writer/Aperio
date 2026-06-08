package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/writer/aperio/internal/config"
)

const testAuthSecret = "example-auth-secret-for-unit-tests-1234567890"

func TestOAuthStateRoundTrip(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)

	original := googleOAuthState{OrganizationID: "org1", UserID: "user1", Role: "ADMIN", Mode: "REMEDIATION", Exp: time.Now().Add(time.Minute).Unix()}
	token, err := encodeOAuthState(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeOAuthState(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.OrganizationID != "org1" || decoded.UserID != "user1" || decoded.Role != "ADMIN" || decoded.Mode != "REMEDIATION" {
		t.Fatalf("decoded state mismatch: %+v", decoded)
	}
}

func TestOAuthStateRejectsTamperedSignature(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)
	token, err := encodeOAuthState(googleOAuthState{OrganizationID: "org1", Exp: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("not-the-signature"))
	if _, err := decodeOAuthState(tampered); err == nil {
		t.Fatal("expected tampered signature to be rejected")
	}
}

func TestOAuthStateRejectsExpired(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)
	token, err := encodeOAuthState(googleOAuthState{OrganizationID: "org1", Exp: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decodeOAuthState(token); err == nil {
		t.Fatal("expected expired state to be rejected")
	}
}

func TestDecodeJWTPayload(t *testing.T) {
	payload, _ := json.Marshal(googleIdentityClaims{Email: "admin@example.com", HD: "example.com"})
	token := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	claims, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("decode jwt: %v", err)
	}
	if claims.Email != "admin@example.com" || claims.HD != "example.com" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestCompatGoogleOAuthStartBuildsAuthorizationURL(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)
	t.Setenv("GOOGLE_WORKSPACE_CLIENT_ID", "client-id-123")
	t.Setenv("GOOGLE_WORKSPACE_CLIENT_SECRET", "client-secret-456")
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "https://api.example.com/api/v1/integrations/google-workspace/oauth/callback")

	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	result, err := app.compatGoogleOAuthStart(context.Background(), map[string]any{"mode": "READ_ONLY"}, compatAuth{OrganizationID: "org1", UserID: "user1", Role: "ADMIN"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	data := result.(map[string]any)["data"].(map[string]string)
	parsed, err := url.Parse(data["url"])
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if parsed.Host != "accounts.google.com" {
		t.Fatalf("unexpected host: %s", parsed.Host)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client-id-123" {
		t.Fatalf("client_id = %s", query.Get("client_id"))
	}
	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Fatalf("missing offline/consent params: %s", parsed.RawQuery)
	}
	scope := query.Get("scope")
	if !strings.Contains(scope, "openid") || !strings.Contains(scope, "email") || !strings.Contains(scope, "profile") {
		t.Fatalf("scope missing base scopes: %s", scope)
	}
	state, err := decodeOAuthState(query.Get("state"))
	if err != nil {
		t.Fatalf("decode state from url: %v", err)
	}
	if state.OrganizationID != "org1" || state.Mode != "READ_ONLY" {
		t.Fatalf("state mismatch: %+v", state)
	}
}

func TestFirstConfiguredWebOriginUsesFirstCommaSeparatedOrigin(t *testing.T) {
	origin := firstConfiguredWebOrigin(" https://app.example.com/, https://staging.example.com ")
	if origin != "https://app.example.com" {
		t.Fatalf("unexpected origin %q", origin)
	}
}

func TestCompatGoogleOAuthStartUnconfigured(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)
	t.Setenv("GOOGLE_WORKSPACE_CLIENT_ID", "")
	t.Setenv("GOOGLE_WORKSPACE_CLIENT_SECRET", "")
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "")

	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	_, err := app.compatGoogleOAuthStart(context.Background(), map[string]any{"mode": "READ_ONLY"}, compatAuth{OrganizationID: "org1"})
	if err == nil {
		t.Fatal("expected unconfigured OAuth to error")
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("expected CodeFailedPrecondition, got %v", connect.CodeOf(err))
	}
}

func TestDefaultGoogleOAuthRedirectURIFromEnv(t *testing.T) {
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "https://api.example.com/api/v1/integrations/google-workspace/oauth/callback")
	if got := defaultGoogleOAuthRedirectURI(); got != "https://api.example.com/api/v1/integrations/google-workspace/oauth/callback" {
		t.Fatalf("env redirect not preferred: %s", got)
	}
}

// TestDefaultGoogleOAuthRedirectURIFallsBackToConnectAddr pins the
// localhost-not-127.0.0.1 default so a future regression that flips the host
// breaks loud. The browser stores the session cookie against the host the web
// UI talked to (localhost), and the callback must arrive at that same host or
// the cookie is missing and compatAuthFromSession returns "missing session".
func TestDefaultGoogleOAuthRedirectURIFallsBackToConnectAddr(t *testing.T) {
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "")
	t.Setenv("APERIO_PUBLIC_API_ORIGIN", "")
	t.Setenv("APERIO_CONNECT_ADDR", ":4100")
	got := defaultGoogleOAuthRedirectURI()
	if got != "http://localhost:4100/api/v1/integrations/google-workspace/oauth/callback" {
		t.Fatalf("unexpected redirect uri: %s", got)
	}
}

func TestDefaultGoogleOAuthRedirectURIPrefersPublicAPIOrigin(t *testing.T) {
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "")
	t.Setenv("APERIO_PUBLIC_API_ORIGIN", "https://api.example.com")
	t.Setenv("APERIO_CONNECT_ADDR", ":4100")
	got := defaultGoogleOAuthRedirectURI()
	if got != "https://api.example.com/api/v1/integrations/google-workspace/oauth/callback" {
		t.Fatalf("APERIO_PUBLIC_API_ORIGIN should win: %s", got)
	}
}

func TestDefaultGoogleOAuthRedirectURIWithoutConnectAddr(t *testing.T) {
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "")
	t.Setenv("APERIO_PUBLIC_API_ORIGIN", "")
	t.Setenv("APERIO_CONNECT_ADDR", "")
	got := defaultGoogleOAuthRedirectURI()
	if got != "http://localhost:4100/api/v1/integrations/google-workspace/oauth/callback" {
		t.Fatalf("unset addr should default to localhost:4100, got %s", got)
	}
}

func TestDefaultGoogleOAuthRedirectURINormalizesScheme(t *testing.T) {
	t.Setenv("GOOGLE_WORKSPACE_REDIRECT_URI", "")
	t.Setenv("APERIO_PUBLIC_API_ORIGIN", "")
	t.Setenv("APERIO_CONNECT_ADDR", "https://api.example.com:443")
	got := defaultGoogleOAuthRedirectURI()
	if got != "https://api.example.com:443/api/v1/integrations/google-workspace/oauth/callback" {
		t.Fatalf("https addr not honored: %s", got)
	}
}

func TestOAuthClientSecretAAD(t *testing.T) {
	if oauthClientSecretAAD("org1", "GOOGLE_WORKSPACE") != "oauth-client:org1:GOOGLE_WORKSPACE" {
		t.Fatal("AAD shape changed; existing per-tenant secrets will fail to decrypt")
	}
}
