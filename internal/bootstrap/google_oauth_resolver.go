package bootstrap

import (
	"context"
	"database/sql"
	"strings"

	"github.com/writer/aperio/internal/runtimeutil"
)

// GoogleOAuthResolver is a small, dependency-free adapter that satisfies
// internal/googleworkspacepoller.OAuthResolver without forcing that package
// to import bootstrap (which would create an import cycle: bootstrap → poller
// → bootstrap). The resolver reads per-tenant client credentials from
// integration_oauth_clients, falls back to the operator env vars, and decrypts
// the stored client_secret using the same AAD scheme the rest of the bootstrap
// package uses (oauthClientSecretAAD).
type GoogleOAuthResolver struct {
	DB *sql.DB
}

// ResolveGoogleOAuthClient returns the per-organization Google OAuth client
// id / secret pair. The bool is false when neither a per-tenant row nor the
// operator env fallback is configured, in which case the caller should skip
// the integration with a log line rather than fail loudly.
func (r GoogleOAuthResolver) ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (poolerOAuthConfig, bool) {
	if r.DB != nil && strings.TrimSpace(organizationID) != "" {
		var clientID, encryptedSecret string
		err := r.DB.QueryRowContext(ctx, `
			SELECT client_id, encrypted_client_secret
			FROM integration_oauth_clients
			WHERE organization_id = $1 AND provider = 'GOOGLE_WORKSPACE'
		`, organizationID).Scan(&clientID, &encryptedSecret)
		if err == nil && clientID != "" && encryptedSecret != "" {
			plain, decErr := runtimeutil.DecryptString(encryptedSecret, oauthClientSecretAAD(organizationID, "GOOGLE_WORKSPACE"))
			if decErr == nil && plain != "" {
				return poolerOAuthConfig{ClientID: clientID, ClientSecret: plain}, true
			}
		}
	}
	if env := resolveGoogleOAuthConfig(); env != nil {
		return poolerOAuthConfig{ClientID: env.clientID, ClientSecret: env.clientSecret}, true
	}
	return poolerOAuthConfig{}, false
}

// poolerOAuthConfig mirrors googleworkspacepoller.OAuthConfig structurally so
// the bootstrap package does not need to import the poller package. Keeping
// the type local also keeps the test surface here free of the poller's
// transitive dependencies. The concrete poller adapter in cmd/google-workspace-poller
// translates between the two shapes.
type poolerOAuthConfig struct {
	ClientID     string
	ClientSecret string
}
