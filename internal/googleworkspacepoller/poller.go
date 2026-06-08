// Package googleworkspacepoller pulls Google Workspace audit activities from
// the Google Admin Reports API and enqueues them into ingestion_jobs so the
// existing rule evaluators (internal/ingestionworker) can produce findings.
//
// Why a separate package: the ingestion worker is a pure consumer of queued
// jobs. Until this package landed, no producer existed for Google Workspace,
// so connecting Google via OAuth stored a refresh token that nothing ever
// used. The poller closes that gap.
//
// Design notes:
//   - Per integration, per Google application (admin, drive, token, login) we
//     keep a cursor (event time + uniqueQualifier) in google_workspace_sync_cursors.
//     Both fields are required because Google guarantees uniqueness only on the
//     pair, not on time alone.
//   - The first poll for a fresh integration only pulls the most recent 24h.
//     Older history is intentionally skipped to avoid drowning a new tenant in
//     stale findings.
//   - We translate Google's raw event names into the Aperio synthesized event
//     types the worker matches against (EXTERNAL_SHARING_ENABLED, etc). When a
//     Google event does not map cleanly we fall through with the raw uppercase
//     name so future rule additions can match without a poller change.
//   - HTTP failures on a single integration log and update last_error, but do
//     not stop the sweep. One broken tenant should not freeze ingestion for the
//     rest of the fleet.
package googleworkspacepoller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/writer/aperio/internal/runtimeutil"
)

const (
	defaultPollInterval = 60 * time.Second
	defaultLookback     = 24 * time.Hour
	tokenURL            = "https://oauth2.googleapis.com/token"
	reportsBaseURL      = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
	maxActivitiesPerApp = 200
)

// DefaultApplications is the set of Google audit applications the poller
// covers. login is intentionally omitted from the default set because the
// existing worker has no login-specific rules; adding it would only inflate
// ingestion_jobs without producing findings. Add it back once login rules
// land in internal/ingestionworker.
var DefaultApplications = []string{"admin", "drive", "token"}

// OAuthConfig is the credential bundle needed for one token-exchange call.
// The poller resolves a fresh OAuthConfig per integration so per-tenant OAuth
// client rotation in integration_oauth_clients takes effect on the next sweep
// without a process restart.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
}

// OAuthResolver returns the OAuth client credentials for an organization.
// It is an interface so the bootstrap package's resolver
// (resolveGoogleOAuthConfigForOrg) can be injected without an import cycle.
type OAuthResolver interface {
	ResolveGoogleOAuthClient(ctx context.Context, organizationID string) (OAuthConfig, bool)
}

// Poller is the long-running goroutine that drives Google Workspace ingestion.
// Construct via New and start with Run.
type Poller struct {
	db            *sql.DB
	httpClient    *http.Client
	resolver      OAuthResolver
	interval      time.Duration
	lookback      time.Duration
	applications  []string
	nowFn         func() time.Time
	maxActivities int
}

// New builds a Poller with sensible defaults. The HTTP client is given a
// 20 second timeout to bound stuck Google requests; tune via Poller.httpClient
// in tests if needed.
func New(db *sql.DB, resolver OAuthResolver) *Poller {
	return &Poller{
		db:            db,
		httpClient:    &http.Client{Timeout: 20 * time.Second},
		resolver:      resolver,
		interval:      defaultPollInterval,
		lookback:      defaultLookback,
		applications:  append([]string(nil), DefaultApplications...),
		nowFn:         time.Now,
		maxActivities: maxActivitiesPerApp,
	}
}

// WithInterval overrides the poll interval. Useful in tests; production
// callers should accept the default.
func (p *Poller) WithInterval(d time.Duration) *Poller { p.interval = d; return p }

// WithHTTPClient swaps the HTTP client. Used in tests to point at a httptest
// server. The provided client should set its own timeout.
func (p *Poller) WithHTTPClient(c *http.Client) *Poller { p.httpClient = c; return p }

// WithApplications overrides which Google audit applications to poll.
func (p *Poller) WithApplications(apps []string) *Poller {
	p.applications = append([]string(nil), apps...)
	return p
}

// WithNowFn overrides the wall clock; tests inject a deterministic clock so
// cursor and lookback assertions are stable.
func (p *Poller) WithNowFn(fn func() time.Time) *Poller { p.nowFn = fn; return p }

// Run blocks until ctx is cancelled, ticking the poller every interval.
// Each tick is independent: a tick error does not abort the loop, since the
// only durable state lives in google_workspace_sync_cursors and ingestion_jobs.
func (p *Poller) Run(ctx context.Context) error {
	// Run an immediate tick on start so freshly-connected integrations don't
	// have to wait a full interval before any data arrives. Errors are logged
	// but do not stop the loop.
	if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("googleworkspacepoller: first tick failed: %v", err)
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("googleworkspacepoller: tick failed: %v", err)
			}
		}
	}
}

// integrationRow is the projection of integration_connections the poller
// needs. Provider is filtered to GOOGLE_WORKSPACE; status is filtered to
// CONNECTED so disconnected integrations do not waste OAuth quota.
type integrationRow struct {
	ID                string
	OrganizationID    string
	ExternalAccountID string
	EncryptedToken    string
}

// Tick performs one sweep across all connected Google Workspace integrations.
// Exported so tests can drive it deterministically without spinning up a
// goroutine + ticker.
func (p *Poller) Tick(ctx context.Context) error {
	integrations, err := p.connectedIntegrations(ctx)
	if err != nil {
		return fmt.Errorf("list integrations: %w", err)
	}
	for _, integ := range integrations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollIntegration(ctx, integ); err != nil {
			log.Printf("googleworkspacepoller: integration %s poll failed: %v", integ.ID, err)
		}
	}
	return nil
}

func (p *Poller) connectedIntegrations(ctx context.Context) ([]integrationRow, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, organization_id, external_account_id, encrypted_access_token
		FROM integration_connections
		WHERE provider = 'GOOGLE_WORKSPACE' AND status = 'CONNECTED'
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []integrationRow
	for rows.Next() {
		var r integrationRow
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.ExternalAccountID, &r.EncryptedToken); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// pollIntegration handles one integration. It resolves the per-org OAuth
// client, exchanges the stored refresh token for a one-shot access token, and
// fans out one HTTP call per application.
func (p *Poller) pollIntegration(ctx context.Context, integ integrationRow) error {
	oauth, ok := p.resolver.ResolveGoogleOAuthClient(ctx, integ.OrganizationID)
	if !ok {
		return errors.New("oauth client unresolved for organization")
	}
	refreshToken, err := runtimeutil.DecryptString(
		integ.EncryptedToken,
		runtimeutil.IntegrationSecretAAD(integ.OrganizationID, "GOOGLE_WORKSPACE", integ.ExternalAccountID, "access_token"),
	)
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}
	accessToken, err := p.exchangeRefreshToken(ctx, oauth, refreshToken)
	if err != nil {
		return fmt.Errorf("exchange refresh token: %w", err)
	}
	for _, app := range p.applications {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollApplication(ctx, integ, app, accessToken); err != nil {
			// Surface to the cursor row so operators can see why a specific
			// application stopped advancing without grepping logs.
			p.recordError(ctx, integ.ID, app, err)
			log.Printf("googleworkspacepoller: integ=%s app=%s poll failed: %v", integ.ID, app, err)
			continue
		}
	}
	// Best-effort update of integration_connections.last_sync_at so the UI
	// reflects a recent successful sweep even if one application failed.
	_, _ = p.db.ExecContext(ctx, `UPDATE integration_connections SET last_sync_at = $1, updated_at = NOW() WHERE id = $2`, p.nowFn().UTC(), integ.ID)
	return nil
}

// pollApplication lists activities for one (integration, application) pair
// starting from the persisted cursor (or now-lookback on first poll) and
// enqueues each new activity as one ingestion_jobs row per Google event.
func (p *Poller) pollApplication(ctx context.Context, integ integrationRow, application, accessToken string) error {
	cursor, err := p.loadCursor(ctx, integ.ID, application)
	if err != nil {
		return fmt.Errorf("load cursor: %w", err)
	}
	startTime := cursor.LastEventTime
	if startTime.IsZero() {
		startTime = p.nowFn().Add(-p.lookback).UTC()
	}
	activities, err := p.listActivities(ctx, application, accessToken, startTime)
	if err != nil {
		return err
	}
	if len(activities) == 0 {
		p.touchCursor(ctx, integ.ID, application, cursor.LastEventTime, cursor.LastUniqueQualifier)
		return nil
	}
	// Google returns activities ordered DESC; flip to ASC so the cursor
	// advances monotonically as we iterate and we never re-enqueue when a
	// single call already saw a later event than the cursor.
	for i, j := 0, len(activities)-1; i < j; i, j = i+1, j-1 {
		activities[i], activities[j] = activities[j], activities[i]
	}
	latestTime := cursor.LastEventTime
	latestQualifier := cursor.LastUniqueQualifier
	for _, activity := range activities {
		if !cursor.isStrictlyAfter(activity.EventTime, activity.UniqueQualifier) {
			continue
		}
		for _, event := range activity.Events {
			if err := p.enqueueEvent(ctx, integ, application, activity, event); err != nil {
				log.Printf("googleworkspacepoller: enqueue failed integ=%s app=%s id=%s: %v",
					integ.ID, application, activity.UniqueQualifier, err)
				return err
			}
		}
		latestTime = activity.EventTime
		latestQualifier = activity.UniqueQualifier
	}
	p.touchCursor(ctx, integ.ID, application, latestTime, latestQualifier)
	return nil
}

type cursorRow struct {
	LastEventTime       time.Time
	LastUniqueQualifier string
}

func (c cursorRow) isStrictlyAfter(t time.Time, qualifier string) bool {
	if c.LastEventTime.IsZero() {
		return true
	}
	if t.After(c.LastEventTime) {
		return true
	}
	if t.Equal(c.LastEventTime) && qualifier > c.LastUniqueQualifier {
		return true
	}
	return false
}

func (p *Poller) loadCursor(ctx context.Context, integrationID, application string) (cursorRow, error) {
	var c cursorRow
	err := p.db.QueryRowContext(ctx, `
		SELECT last_event_time, last_unique_qualifier
		FROM google_workspace_sync_cursors
		WHERE integration_id = $1 AND application = $2
	`, integrationID, application).Scan(&c.LastEventTime, &c.LastUniqueQualifier)
	if errors.Is(err, sql.ErrNoRows) {
		return cursorRow{}, nil
	}
	return c, err
}

func (p *Poller) touchCursor(ctx context.Context, integrationID, application string, eventTime time.Time, qualifier string) {
	// We always upsert: on first poll the cursor row doesn't exist yet, on
	// subsequent polls it must advance even when no new activities arrived
	// (so last_polled_at moves forward and last_error clears).
	if eventTime.IsZero() {
		eventTime = p.nowFn().Add(-p.lookback).UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_sync_cursors
			(integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
		VALUES ($1, $2, $3, $4, $5, NULL)
		ON CONFLICT (integration_id, application) DO UPDATE SET
			last_event_time = EXCLUDED.last_event_time,
			last_unique_qualifier = EXCLUDED.last_unique_qualifier,
			last_polled_at = EXCLUDED.last_polled_at,
			last_error = NULL
	`, integrationID, application, eventTime, qualifier, p.nowFn().UTC())
	if err != nil {
		log.Printf("googleworkspacepoller: touchCursor failed integ=%s app=%s: %v", integrationID, application, err)
	}
}

func (p *Poller) recordError(ctx context.Context, integrationID, application string, pollErr error) {
	msg := pollErr.Error()
	if len(msg) > 480 {
		msg = msg[:480]
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_sync_cursors
			(integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
		VALUES ($1, $2, $3, '', $4, $5)
		ON CONFLICT (integration_id, application) DO UPDATE SET
			last_polled_at = EXCLUDED.last_polled_at,
			last_error = EXCLUDED.last_error
	`, integrationID, application, p.nowFn().Add(-p.lookback).UTC(), p.nowFn().UTC(), msg)
	if err != nil {
		log.Printf("googleworkspacepoller: recordError failed integ=%s app=%s: %v", integrationID, application, err)
	}
}

// enqueueEvent inserts one ingestion_jobs row per Google event. The event
// type is normalized into the synthesized Aperio constants the existing
// worker matches against, so EXTERNAL_SHARING_ENABLED / SUPER_ADMIN_GRANTED /
// etc work end-to-end without changes to internal/ingestionworker.
func (p *Poller) enqueueEvent(ctx context.Context, integ integrationRow, application string, activity reportsActivity, event reportsEvent) error {
	mapped := MapEventType(application, event.Name, event.Parameters)
	payload := buildJobPayload(application, activity, event)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// Application + activity uniqueQualifier is globally unique within a
	// Google customer; including it in the ingestion_jobs id derivation would
	// be ideal but the schema generates ids itself. We rely on a server-side
	// unique guard via (organization_id, integration_id, source_event_id) at
	// the ingested_events layer once the worker promotes the job. Within the
	// ingestion_jobs table we instead use a best-effort dedupe based on the
	// composite key embedded in the JSON payload's sourceEventId field.
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor,
			occurred_at, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, 'GOOGLE_WORKSPACE', $4, $5, $6, $7, $8::jsonb, 'QUEUED', 0, 3, NOW(), NOW(), NOW())
	`,
		"ijb_"+activity.UniqueQualifier+"_"+event.Name,
		integ.OrganizationID,
		integ.ID,
		mapped,
		"google.reports."+application,
		activity.Actor.Email,
		activity.EventTime,
		payloadJSON,
	)
	if err != nil && isUniqueViolation(err) {
		// Cursor lagged behind a prior enqueue (retry or overlap); skipping
		// keeps the worker queue idempotent.
		return nil
	}
	return err
}

// buildJobPayload flattens Google's array-based parameters into the
// map[string]any shape the existing rule evaluators expect (they call
// nestedString(payload, "parameters", "doc_title") and similar).
func buildJobPayload(application string, activity reportsActivity, event reportsEvent) map[string]any {
	parameters := map[string]any{}
	for _, param := range event.Parameters {
		if param.MultiValue != nil {
			parameters[param.Name] = param.MultiValue
			continue
		}
		if param.IntValue != "" {
			parameters[param.Name] = param.IntValue
			continue
		}
		if param.BoolValue != nil {
			parameters[param.Name] = *param.BoolValue
			continue
		}
		parameters[param.Name] = param.Value
	}
	payload := map[string]any{
		"application":   application,
		"parameters":    parameters,
		"sourceEventId": activity.UniqueQualifier,
		"ownerDomain":   ownerDomainFromActor(activity.Actor.Email),
	}
	if name, ok := parameters["doc_title"].(string); ok && name != "" {
		payload["resource"] = map[string]any{"name": name, "id": stringParam(parameters, "doc_id")}
	}
	if email := stringParam(parameters, "USER_EMAIL"); email != "" {
		payload["target"] = map[string]any{"email": email}
	} else if email := stringParam(parameters, "user_email"); email != "" {
		payload["target"] = map[string]any{"email": email}
	}
	return payload
}

func stringParam(parameters map[string]any, key string) string {
	if v, ok := parameters[key].(string); ok {
		return v
	}
	return ""
}

func ownerDomainFromActor(email string) string {
	if at := strings.LastIndex(email, "@"); at >= 0 {
		return strings.ToLower(email[at+1:])
	}
	return ""
}

// reportsActivity mirrors the subset of Google's Activity resource we use.
// We intentionally don't model every field — only what the rule evaluators
// read — so future Reports API additions can pass through untouched.
type reportsActivity struct {
	EventTime       time.Time
	UniqueQualifier string
	Actor           reportsActor
	Events          []reportsEvent
}

type reportsActor struct {
	Email      string `json:"email"`
	ProfileID  string `json:"profileId"`
	CallerType string `json:"callerType"`
}

type reportsEvent struct {
	Type       string             `json:"type"`
	Name       string             `json:"name"`
	Parameters []reportsParameter `json:"parameters"`
}

type reportsParameter struct {
	Name       string   `json:"name"`
	Value      string   `json:"value,omitempty"`
	IntValue   string   `json:"intValue,omitempty"`
	BoolValue  *bool    `json:"boolValue,omitempty"`
	MultiValue []string `json:"multiValue,omitempty"`
}

type reportsResponse struct {
	Items []struct {
		ID struct {
			Time            time.Time `json:"time"`
			UniqueQualifier string    `json:"uniqueQualifier"`
			ApplicationName string    `json:"applicationName"`
			CustomerID      string    `json:"customerId"`
		} `json:"id"`
		Actor  reportsActor   `json:"actor"`
		Events []reportsEvent `json:"events"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}

func (p *Poller) listActivities(ctx context.Context, application, accessToken string, startTime time.Time) ([]reportsActivity, error) {
	endpoint := reportsBaseURL + "/" + url.PathEscape(application)
	q := url.Values{}
	// startTime is exclusive on Google's side; our cursor comparison adds a
	// strict-after check anyway so the boundary is correct either way.
	q.Set("startTime", startTime.UTC().Format(time.RFC3339))
	q.Set("maxResults", "1000")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Surface a truncated body so operators can see Google's error JSON
		// without us round-tripping the entire payload into our logs.
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, fmt.Errorf("google reports api %d: %s", resp.StatusCode, snippet)
	}
	var decoded reportsResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode reports response: %w", err)
	}
	out := make([]reportsActivity, 0, len(decoded.Items))
	for _, item := range decoded.Items {
		out = append(out, reportsActivity{
			EventTime:       item.ID.Time.UTC(),
			UniqueQualifier: item.ID.UniqueQualifier,
			Actor:           item.Actor,
			Events:          item.Events,
		})
		if len(out) >= p.maxActivities {
			break
		}
	}
	return out, nil
}

// exchangeRefreshToken converts the stored Google refresh token into a
// short-lived access token. We intentionally do NOT persist the access
// token; Google's refresh tokens are durable and re-exchange is cheap.
func (p *Poller) exchangeRefreshToken(ctx context.Context, oauth OAuthConfig, refreshToken string) (string, error) {
	form := url.Values{}
	form.Set("client_id", oauth.ClientID)
	form.Set("client_secret", oauth.ClientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return "", fmt.Errorf("token exchange %d: %s", resp.StatusCode, snippet)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("token exchange response missing access_token")
	}
	return decoded.AccessToken, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key")
}
