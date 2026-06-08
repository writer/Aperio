package bootstrap

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/config"
)

func TestNormalizeOAuthProvider(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"google_workspace", "GOOGLE_WORKSPACE", false},
		{"GOOGLE_WORKSPACE", "GOOGLE_WORKSPACE", false},
		{" google_workspace ", "GOOGLE_WORKSPACE", false},
		{"github", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeOAuthProvider(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", tc.in)
			}
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("%q: expected InvalidArgument, got %v", tc.in, connect.CodeOf(err))
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestSetIntegrationOAuthClientValidation(t *testing.T) {
	t.Setenv("APERIO_AUTH_SECRET", testAuthSecret)
	app := NewApp(config.Config{}, nil)

	cases := []struct {
		name string
		req  *aperiov1.SetIntegrationOAuthClientRequest
	}{
		{"missing client id", &aperiov1.SetIntegrationOAuthClientRequest{Provider: "GOOGLE_WORKSPACE", ClientSecret: "secret", RedirectUri: "https://example.com/cb"}},
		{"missing client secret", &aperiov1.SetIntegrationOAuthClientRequest{Provider: "GOOGLE_WORKSPACE", ClientId: "abc", RedirectUri: "https://example.com/cb"}},
		{"missing redirect", &aperiov1.SetIntegrationOAuthClientRequest{Provider: "GOOGLE_WORKSPACE", ClientId: "abc", ClientSecret: "secret"}},
		{"non-http redirect", &aperiov1.SetIntegrationOAuthClientRequest{Provider: "GOOGLE_WORKSPACE", ClientId: "abc", ClientSecret: "secret", RedirectUri: "ftp://example.com/cb"}},
		{"unsupported provider", &aperiov1.SetIntegrationOAuthClientRequest{Provider: "GITHUB", ClientId: "abc", ClientSecret: "secret", RedirectUri: "https://example.com/cb"}},
	}
	for _, tc := range cases {
		_, err := app.SetIntegrationOAuthClient(context.Background(), &connect.Request[aperiov1.SetIntegrationOAuthClientRequest]{Msg: tc.req})
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		code := connect.CodeOf(err)
		if code != connect.CodeInvalidArgument && code != connect.CodeUnauthenticated {
			t.Fatalf("%s: unexpected code %v", tc.name, code)
		}
	}
}

func TestOAuthClientResponseShape(t *testing.T) {
	got := oauthClientResponse("GOOGLE_WORKSPACE", nil)
	if got.Configured {
		t.Fatal("nil record should report configured=false")
	}
	if got.Provider != "GOOGLE_WORKSPACE" {
		t.Fatalf("provider mismatch: %q", got.Provider)
	}
	if got.DefaultRedirectUri == "" {
		t.Fatal("default redirect URI should be populated")
	}
}
