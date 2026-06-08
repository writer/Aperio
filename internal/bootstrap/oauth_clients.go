package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
)

// Providers that currently support per-organization OAuth client credentials
// configured from the admin UI. Add to this list as providers are wired up.
var oauthClientSupportedProviders = map[string]bool{
	"GOOGLE_WORKSPACE": true,
}

func normalizeOAuthProvider(raw string) (string, error) {
	provider := strings.ToUpper(strings.TrimSpace(raw))
	if !oauthClientSupportedProviders[provider] {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported OAuth provider"))
	}
	return provider, nil
}

type oauthClientRecord struct {
	provider    string
	clientID    string
	redirectURI string
	updatedAt   time.Time
}

func (a *App) loadOAuthClient(ctx context.Context, organizationID string, provider string) (*oauthClientRecord, error) {
	if a.db == nil {
		return nil, nil
	}
	var rec oauthClientRecord
	rec.provider = provider
	err := a.db.QueryRowContext(ctx, `
		SELECT client_id, redirect_uri, updated_at
		FROM integration_oauth_clients
		WHERE organization_id = $1 AND provider = $2::"SaaSProvider"
	`, organizationID, provider).Scan(&rec.clientID, &rec.redirectURI, &rec.updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func defaultRedirectURIFor(provider string) string {
	switch provider {
	case "GOOGLE_WORKSPACE":
		return defaultGoogleOAuthRedirectURI()
	default:
		return ""
	}
}

func oauthClientResponse(provider string, rec *oauthClientRecord) *aperiov1.IntegrationOAuthClient {
	out := &aperiov1.IntegrationOAuthClient{
		Provider:           provider,
		DefaultRedirectUri: defaultRedirectURIFor(provider),
		Configured:         rec != nil,
	}
	if rec != nil {
		out.ClientId = rec.clientID
		out.RedirectUri = rec.redirectURI
		if !rec.updatedAt.IsZero() {
			out.UpdatedAt = rec.updatedAt.UTC().Format(time.RFC3339)
		}
	}
	return out
}

func (a *App) GetIntegrationOAuthClient(
	ctx context.Context,
	req *connect.Request[aperiov1.GetIntegrationOAuthClientRequest],
) (*connect.Response[aperiov1.GetIntegrationOAuthClientResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	provider, err := normalizeOAuthProvider(req.Msg.Provider)
	if err != nil {
		return nil, err
	}
	rec, err := a.loadOAuthClient(ctx, auth.OrganizationID, provider)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client lookup failed"))
	}
	return connect.NewResponse(&aperiov1.GetIntegrationOAuthClientResponse{
		Data: oauthClientResponse(provider, rec),
	}), nil
}

func (a *App) SetIntegrationOAuthClient(
	ctx context.Context,
	req *connect.Request[aperiov1.SetIntegrationOAuthClientRequest],
) (*connect.Response[aperiov1.SetIntegrationOAuthClientResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	provider, err := normalizeOAuthProvider(req.Msg.Provider)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(req.Msg.ClientId)
	clientSecret := strings.TrimSpace(req.Msg.ClientSecret)
	redirectURI := strings.TrimSpace(req.Msg.RedirectUri)
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("clientId, clientSecret, and redirectUri are required"))
	}
	if len(clientID) > 500 || len(redirectURI) > 500 || len(clientSecret) > 4096 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("OAuth client values exceed allowed length"))
	}
	if !strings.HasPrefix(strings.ToLower(redirectURI), "http://") && !strings.HasPrefix(strings.ToLower(redirectURI), "https://") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("redirectUri must be an absolute http(s) URL"))
	}
	if a.db == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("database is required"))
	}
	encrypted, err := compatEncryptString(clientSecret, oauthClientSecretAAD(auth.OrganizationID, provider))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client encryption failed"))
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client persist failed"))
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var updatedAt time.Time
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO integration_oauth_clients (id, organization_id, provider, client_id, encrypted_client_secret, redirect_uri, token_key_version, created_by_id, created_at, updated_at)
		VALUES ($1, $2, $3::"SaaSProvider", $4, $5, $6, 'v1', $7, NOW(), NOW())
		ON CONFLICT (organization_id, provider) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			encrypted_client_secret = EXCLUDED.encrypted_client_secret,
			redirect_uri = EXCLUDED.redirect_uri,
			token_key_version = EXCLUDED.token_key_version,
			updated_at = NOW()
		RETURNING updated_at
	`, compatID("oac"), auth.OrganizationID, provider, clientID, encrypted, redirectURI, nullableUserID(auth.UserID)).Scan(&updatedAt); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client persist failed"))
	}

	if err := writeOAuthClientAudit(ctx, tx, auth, provider, "integration.oauth_client.set", map[string]any{
		"clientId":    clientID,
		"redirectUri": redirectURI,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client audit failed"))
	}

	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client persist failed"))
	}
	committed = true

	rec := &oauthClientRecord{provider: provider, clientID: clientID, redirectURI: redirectURI, updatedAt: updatedAt}
	return connect.NewResponse(&aperiov1.SetIntegrationOAuthClientResponse{
		Data: oauthClientResponse(provider, rec),
	}), nil
}

func (a *App) ClearIntegrationOAuthClient(
	ctx context.Context,
	req *connect.Request[aperiov1.ClearIntegrationOAuthClientRequest],
) (*connect.Response[aperiov1.ClearIntegrationOAuthClientResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	provider, err := normalizeOAuthProvider(req.Msg.Provider)
	if err != nil {
		return nil, err
	}
	if a.db == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("database is required"))
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client clear failed"))
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	res, err := tx.ExecContext(ctx, `
		DELETE FROM integration_oauth_clients
		WHERE organization_id = $1 AND provider = $2::"SaaSProvider"
	`, auth.OrganizationID, provider)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client clear failed"))
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		if err := writeOAuthClientAudit(ctx, tx, auth, provider, "integration.oauth_client.clear", nil); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client audit failed"))
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("oauth client clear failed"))
	}
	committed = true

	return connect.NewResponse(&aperiov1.ClearIntegrationOAuthClientResponse{
		Data: oauthClientResponse(provider, nil),
	}), nil
}

func nullableUserID(id string) any {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return id
}

func writeOAuthClientAudit(ctx context.Context, tx *sql.Tx, auth compatAuth, provider string, action string, extra map[string]any) error {
	metadata := map[string]any{"provider": provider}
	for k, v := range extra {
		metadata[k] = v
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, ip_address, metadata, created_at) VALUES ($1,$2,$3,$4,'integration_oauth_client',$5,NULL,$6,NOW())`,
		compatID("aud"), auth.OrganizationID, nullableUserID(auth.UserID), action, provider, encoded)
	return err
}
