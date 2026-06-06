package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
)

// This file ports the Google Workspace OAuth flow from the original
// apps/api/src/routes/integrations.ts. The authorization URL and HMAC-signed
// state token are produced by the Connect-served start endpoint, while the
// browser redirect callback is a plain HTTP route that exchanges the
// authorization code, persists encrypted tokens, and bounces back to the web app.

type googleOAuthConfig struct {
	clientID     string
	clientSecret string
	redirectURI  string
	webOrigin    string
}

type googleOAuthState struct {
	OrganizationID string `json:"organizationId"`
	UserID         string `json:"userId"`
	Role           string `json:"role"`
	Mode           string `json:"mode"`
	Exp            int64  `json:"exp"`
}

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type googleIdentityClaims struct {
	Email string `json:"email"`
	HD    string `json:"hd"`
}

type googleIntegrationUpsert struct {
	organizationID    string
	userID            string
	externalAccountID string
	displayName       string
	mode              string
	refreshToken      string
	adminEmail        string
	requestIP         string
}

func resolveGoogleOAuthConfig() *googleOAuthConfig {
	clientID := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_CLIENT_SECRET"))
	redirectURI := strings.TrimSpace(os.Getenv("GOOGLE_WORKSPACE_REDIRECT_URI"))
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil
	}
	webOrigin := strings.TrimRight(envOrDefault("APERIO_WEB_ORIGIN", envOrDefault("NEXT_PUBLIC_APP_BASE_URL", "http://localhost:3000")), "/")
	return &googleOAuthConfig{clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI, webOrigin: webOrigin}
}

func oauthStateSecret() ([]byte, error) {
	secret := os.Getenv("APERIO_AUTH_SECRET")
	if len(secret) < 32 {
		return nil, errors.New("invalid authentication configuration")
	}
	return []byte(secret), nil
}

func encodeOAuthState(state googleOAuthState) (string, error) {
	secret, err := oauthStateSecret()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	// Sign the encoded body rather than raw JSON so decoding is unambiguous and
	// the callback can reject tampering before allocating the state struct.
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + signature, nil
}

func decodeOAuthState(token string) (googleOAuthState, error) {
	var state googleOAuthState
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return state, errors.New("invalid OAuth state")
	}
	secret, err := oauthStateSecret()
	if err != nil {
		return state, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	// Constant-time comparison avoids leaking which signature bytes matched for
	// attacker-supplied state tokens.
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) != 1 {
		return state, errors.New("invalid OAuth state")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return state, errors.New("invalid OAuth state")
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, errors.New("invalid OAuth state")
	}
	if state.Exp*1000 < time.Now().UnixMilli() {
		// State tokens are short-lived because they authorize binding a Google
		// Workspace tenant to the current Aperio organization.
		return state, errors.New("OAuth state expired")
	}
	return state, nil
}

func decodeJWTPayload(token string) (googleIdentityClaims, error) {
	var claims googleIdentityClaims
	parts := strings.Split(token, ".")
	if len(parts) < 2 || parts[1] == "" {
		return claims, errors.New("invalid identity token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("invalid identity token")
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, errors.New("invalid identity token")
	}
	return claims, nil
}

func (a *App) compatGoogleOAuthStart(body map[string]any, auth compatAuth) (any, error) {
	mode := strings.ToUpper(stringDefault(body, "mode", "READ_ONLY"))
	if mode != "READ_ONLY" && mode != "REMEDIATION" {
		mode = "READ_ONLY"
	}
	config := resolveGoogleOAuthConfig()
	if config == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("Google Workspace OAuth is not configured. Set GOOGLE_WORKSPACE_CLIENT_ID, GOOGLE_WORKSPACE_CLIENT_SECRET, and GOOGLE_WORKSPACE_REDIRECT_URI."))
	}
	state, err := encodeOAuthState(googleOAuthState{
		OrganizationID: auth.OrganizationID,
		UserID:         auth.UserID,
		Role:           auth.Role,
		Mode:           mode,
		Exp:            time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	scopes := append([]string{"openid", "email", "profile"}, compatScopesForMode("GOOGLE_WORKSPACE", mode)...)
	// prompt=consent and access_type=offline are required to receive a refresh
	// token on reconnect, which the ingestion worker stores as the durable secret.
	authURL, err := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	query := authURL.Query()
	query.Set("client_id", config.clientID)
	query.Set("redirect_uri", config.redirectURI)
	query.Set("response_type", "code")
	query.Set("access_type", "offline")
	query.Set("prompt", "consent")
	query.Set("include_granted_scopes", "true")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	authURL.RawQuery = query.Encode()
	return map[string]any{"data": map[string]string{"url": authURL.String()}}, nil
}

func (a *App) handleGoogleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	config := resolveGoogleOAuthConfig()
	fallbackOrigin := strings.TrimRight(envOrDefault("APERIO_WEB_ORIGIN", "http://localhost:3000"), "/")
	if config != nil {
		fallbackOrigin = config.webOrigin
	}
	redirectError := func(message string) {
		// Errors are returned to the web origin as query parameters; avoid writing
		// provider tokens or internal errors to the browser response body.
		http.Redirect(w, r, fallbackOrigin+"/connectors?google_connect=error&message="+url.QueryEscape(message), http.StatusFound)
	}

	if r.Method != http.MethodGet {
		redirectError("Invalid OAuth callback method")
		return
	}
	query := r.URL.Query()
	if callbackErr := strings.TrimSpace(query.Get("error")); callbackErr != "" {
		redirectError(callbackErr)
		return
	}
	code := strings.TrimSpace(query.Get("code"))
	stateToken := strings.TrimSpace(query.Get("state"))
	if code == "" || stateToken == "" {
		redirectError("Missing OAuth callback parameters")
		return
	}
	if config == nil {
		redirectError("Google Workspace OAuth is not configured")
		return
	}
	state, err := decodeOAuthState(stateToken)
	if err != nil {
		redirectError(err.Error())
		return
	}
	tokens, err := exchangeGoogleAuthCode(r.Context(), config, code)
	if err != nil {
		redirectError("Unable to exchange Google authorization code")
		return
	}
	if tokens.RefreshToken == "" || tokens.IDToken == "" {
		redirectError("Google did not return an offline refresh token")
		return
	}
	identity, err := decodeJWTPayload(tokens.IDToken)
	if err != nil {
		redirectError("Unable to determine the Google Workspace admin identity")
		return
	}
	adminEmail := strings.ToLower(strings.TrimSpace(identity.Email))
	hostedDomain := strings.ToLower(strings.TrimSpace(identity.HD))
	if hostedDomain == "" && strings.Contains(adminEmail, "@") {
		// Google may omit the hosted-domain claim for some enterprise identities;
		// derive it from the verified email so the externalAccountID stays stable.
		hostedDomain = strings.ToLower(strings.TrimSpace(adminEmail[strings.LastIndex(adminEmail, "@")+1:]))
	}
	if adminEmail == "" || hostedDomain == "" {
		redirectError("Unable to determine the Google Workspace admin identity")
		return
	}

	if err := a.upsertGoogleWorkspaceIntegration(r.Context(), googleIntegrationUpsert{
		organizationID:    state.OrganizationID,
		userID:            state.UserID,
		externalAccountID: hostedDomain,
		displayName:       "Google Workspace – " + hostedDomain,
		mode:              state.Mode,
		refreshToken:      tokens.RefreshToken,
		adminEmail:        adminEmail,
		requestIP:         clientIP(r),
	}); err != nil {
		redirectError(err.Error())
		return
	}

	http.Redirect(w, r, fallbackOrigin+"/connectors?google_connect=success&provider=google-workspace", http.StatusFound)
}

func exchangeGoogleAuthCode(ctx context.Context, config *googleOAuthConfig, code string) (googleTokenResponse, error) {
	var tokens googleTokenResponse
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", config.clientID)
	form.Set("client_secret", config.clientSecret)
	form.Set("redirect_uri", config.redirectURI)
	form.Set("grant_type", "authorization_code")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return tokens, err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	// Token exchange is the only outbound OAuth call in this flow; the callback
	// does not trust browser-supplied identity data and relies on Google's token
	// response instead.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokens, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokens, errors.New("token exchange failed")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokens, err
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return tokens, err
	}
	return tokens, nil
}

func (a *App) upsertGoogleWorkspaceIntegration(ctx context.Context, input googleIntegrationUpsert) error {
	const provider = "GOOGLE_WORKSPACE"
	// Store the refresh token in the access-token slot because the ingestion
	// worker validates that field when processing queued Google Workspace events.
	encryptedAccess, err := compatEncryptString(input.refreshToken, compatIntegrationSecretAAD(input.organizationID, provider, input.externalAccountID, "access_token"))
	if err != nil {
		return errors.New("integration credential encryption failed")
	}
	encryptedRefresh, err := compatEncryptString(input.adminEmail, compatIntegrationSecretAAD(input.organizationID, provider, input.externalAccountID, "refresh_token"))
	if err != nil {
		return errors.New("integration credential encryption failed")
	}
	scopes := compatScopesForMode(provider, input.mode)
	disabledChecks := compatDefaultDisabledChecks(provider)

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var integrationID string
	var inserted bool
	// Reconnecting the same Workspace domain rotates credentials in place while
	// preserving findings, assets, SIEM subscriptions, and audit history tied to
	// the integration id.
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO integration_connections (id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks, encrypted_access_token, encrypted_refresh_token, token_key_version, status, mode, created_at, updated_at)
		VALUES ($1,$2,'GOOGLE_WORKSPACE',$3,$4,$5,$6,$7,$8,'v1','CONNECTED',$9,NOW(),NOW())
		ON CONFLICT (organization_id, provider, external_account_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			scopes = EXCLUDED.scopes,
			disabled_checks = EXCLUDED.disabled_checks,
			mode = EXCLUDED.mode,
			encrypted_access_token = EXCLUDED.encrypted_access_token,
			encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
			status = 'CONNECTED',
			updated_at = NOW()
		RETURNING id, (xmax = 0)
	`, compatID("int"), input.organizationID, input.displayName, input.externalAccountID, scopes, disabledChecks, encryptedAccess, encryptedRefresh, input.mode).Scan(&integrationID, &inserted); err != nil {
		return err
	}

	if inserted {
		// Create a first-class application asset on initial connect so the security
		// overview graph has an entry point before detailed discovery completes.
		isPrivileged := input.mode == "REMEDIATION"
		riskScore := 35
		if isPrivileged {
			riskScore = 55
		}
		summary := strings.ReplaceAll(provider, "_", " ") + " control plane"
		labels := []string{"integration", strings.ToLower(input.mode)}
		var owner any
		if input.userID != "" {
			owner = input.userID
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO security_assets (id, organization_id, integration_id, owner_user_id, type, provider, name, summary, external_id, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, created_at, updated_at)
			VALUES ($1,$2,$3,$4,'APPLICATION','GOOGLE_WORKSPACE',$5,$6,$7,$8,'HIGH','INTERNAL','ASSIGNED',false,$9,$10,NOW(),NOW())
		`, compatID("ast"), input.organizationID, integrationID, owner, input.displayName, summary, input.externalAccountID, labels, isPrivileged, riskScore); err != nil {
			return err
		}
	}

	action := "integration.oauth.connect"
	if !inserted {
		action = "integration.oauth.reconnect"
	}
	metadata, err := json.Marshal(map[string]any{
		"provider":          provider,
		"displayName":       input.displayName,
		"externalAccountId": input.externalAccountID,
		"mode":              input.mode,
		"oauth":             true,
		"adminEmail":        input.adminEmail,
	})
	if err != nil {
		return err
	}
	var actor any
	if input.userID != "" {
		actor = input.userID
	}
	var ip any
	if input.requestIP != "" {
		ip = input.requestIP
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, ip_address, metadata, created_at) VALUES ($1,$2,$3,$4,'integration_connection',$5,$6,$7,NOW())`, compatID("aud"), input.organizationID, actor, action, integrationID, ip, metadata); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if idx := strings.IndexByte(forwarded, ','); idx >= 0 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
