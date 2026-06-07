package ingestionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/siemdispatcher"
	"github.com/writer/aperio/internal/telemetry"
)

func openDBBackedIngestionWorkerDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed ingestion worker tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func readSiemFindingDeliveryReferenceRecord(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "siem-finding-delivery.json"))
	if err != nil {
		t.Fatalf("read SIEM delivery parity fixture: %v", err)
	}
	var fixture struct {
		Payload siemdispatcher.Payload `json:"payload"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode SIEM delivery parity fixture: %v", err)
	}
	return fixture.Payload.Record
}

func testWorkerID(prefix string) string {
	return prefix + "_" + randomID()
}

func seedIngestionWorkerOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	orgID := testWorkerID("org")
	slug := "go-worker-" + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, "Go Worker Test", slug); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID
}

func seedIngestionWorkerIntegration(t *testing.T, db *sql.DB, orgID, provider, status string) string {
	t.Helper()
	integrationID := testWorkerID("int")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, status, mode, created_at, updated_at
		)
		VALUES (
			$1, $2, $3::"SaaSProvider", $4, $5, ARRAY[]::text[], ARRAY[]::text[],
			'test-token', $6::"IntegrationStatus", 'READ_ONLY'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID, provider, provider+" Worker Test", integrationID, status); err != nil {
		t.Fatalf("seed %s integration: %v", provider, err)
	}
	return integrationID
}

func seedIngestionWorkerJob(t *testing.T, db *sql.DB, input struct {
	orgID         string
	integrationID string
	provider      string
	eventType     string
	status        string
	attempts      int
	maxAttempts   int
	leaseOwner    *string
	payload       json.RawMessage
}) string {
	t.Helper()
	jobID := testWorkerID("job")
	if input.payload == nil {
		input.payload = json.RawMessage(`{}`)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor, occurred_at,
			payload, status, attempts, max_attempts, next_attempt_at, lease_owner, lease_expires_at,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4::"SaaSProvider", $5, 'test', 'worker@example.com', $6,
			$7, $8::"IngestionJobStatus", $9, $10, NOW() - INTERVAL '1 minute', $11::text,
			CASE WHEN $11::text IS NULL THEN NULL ELSE NOW() - INTERVAL '1 minute' END,
			NOW(), NOW()
		)
	`, jobID, input.orgID, input.integrationID, input.provider, input.eventType, time.Now().UTC().Add(-time.Minute), input.payload, input.status, input.attempts, input.maxAttempts, input.leaseOwner); err != nil {
		t.Fatalf("seed ingestion job: %v", err)
	}
	return jobID
}

func ingestionJobState(t *testing.T, db *sql.DB, jobID string) (status string, attempts int, leaseOwner sql.NullString, processedAt sql.NullTime, lastError sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, attempts, lease_owner, processed_at, last_error
		FROM ingestion_jobs
		WHERE id = $1
	`, jobID).Scan(&status, &attempts, &leaseOwner, &processedAt, &lastError); err != nil {
		t.Fatalf("query ingestion job %s: %v", jobID, err)
	}
	return status, attempts, leaseOwner, processedAt, lastError
}

func ingestionJobNextAttemptAt(t *testing.T, db *sql.DB, jobID string) time.Time {
	t.Helper()
	var nextAttemptAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT next_attempt_at
		FROM ingestion_jobs
		WHERE id = $1
	`, jobID).Scan(&nextAttemptAt); err != nil {
		t.Fatalf("query ingestion job next attempt %s: %v", jobID, err)
	}
	return nextAttemptAt
}

func captureIngestionTelemetry(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var sink bytes.Buffer
	restore := telemetry.SetOutput(&sink)
	return &sink, restore
}

func decodeWideEvents(t *testing.T, sink *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	events := []map[string]any{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode telemetry line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func requireTelemetryOutcome(t *testing.T, events []map[string]any, outcome string) map[string]any {
	t.Helper()
	for _, event := range events {
		if event["event_name"] == "ingestion.job.process" && event["outcome"] == outcome {
			return event
		}
	}
	t.Fatalf("missing ingestion telemetry outcome %q in %#v", outcome, events)
	return nil
}

type recordingLifecyclePublisher struct {
	t    *testing.T
	db   *sql.DB
	seen []FindingLifecycleEvent
}

func (p *recordingLifecyclePublisher) PublishFindingLifecycle(ctx context.Context, event FindingLifecycleEvent) error {
	p.t.Helper()
	var status string
	if err := p.db.QueryRowContext(ctx, `
		SELECT status::text
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, event.FindingID, event.OrganizationID).Scan(&status); err != nil {
		p.t.Fatalf("lifecycle event published before committed finding was visible: %v", err)
	}
	if status != event.NextStatus {
		p.t.Fatalf("lifecycle event saw committed status %s, want %s", status, event.NextStatus)
	}
	p.seen = append(p.seen, event)
	return nil
}

func TestDrainLeavesUnsupportedIngestionJobsUntouched(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrations := map[string]string{
		"GITHUB":           seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED"),
		"SLACK":            seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED"),
		"OKTA":             seedIngestionWorkerIntegration(t, db, orgID, "OKTA", "CONNECTED"),
		"GOOGLE_WORKSPACE": seedIngestionWorkerIntegration(t, db, orgID, "GOOGLE_WORKSPACE", "CONNECTED"),
	}

	type unsupportedCase struct {
		name        string
		provider    string
		eventType   string
		status      string
		attempts    int
		maxAttempts int
		payload     json.RawMessage
	}
	cases := []unsupportedCase{
		{name: "slack unsupported event", provider: "SLACK", eventType: "WORKSPACE_INVITE_LINK_ENABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)},
		{name: "slack exhausted unsupported event", provider: "SLACK", eventType: "WORKSPACE_INVITE_LINK_ENABLED", status: "FAILED", attempts: 3, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)},
		{name: "okta fallback rule", provider: "OKTA", eventType: "ADMIN_ROLE_ASSIGNED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"actor":{"displayName":"admin@example.com"},"target":[{"type":"User","displayName":"user@example.com"},{"type":"Role","displayName":"Super Admin"}]}`)},
		{name: "google fallback rule", provider: "GOOGLE_WORKSPACE", eventType: "EXTERNAL_SHARING_ENABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"resource":{"name":"Board Deck"},"parameters":{"visibility":"public_on_the_web"}}`)},
		{name: "unknown github event", provider: "GITHUB", eventType: "UNKNOWN_EVENT", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"repository":{"full_name":"writer/private","visibility":"private"}}`)},
	}

	jobIDs := map[string]string{}
	for _, input := range cases {
		jobIDs[input.name] = seedIngestionWorkerJob(t, db, struct {
			orgID         string
			integrationID string
			provider      string
			eventType     string
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
			payload       json.RawMessage
		}{orgID: orgID, integrationID: integrations[input.provider], provider: input.provider, eventType: input.eventType, status: input.status, attempts: input.attempts, maxAttempts: input.maxAttempts, payload: input.payload})
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 0 || result.Succeeded != 0 || result.Failed != 0 {
		t.Fatalf("expected unsupported jobs to remain unprocessed, got %#v", result)
	}

	for _, input := range cases {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobIDs[input.name])
		if status != input.status || attempts != input.attempts || leaseOwner.Valid || processedAt.Valid || lastError.Valid {
			t.Fatalf("%s changed: status=%s attempts=%d lease=%v processed=%v error=%v", input.name, status, attempts, leaseOwner, processedAt, lastError)
		}
	}
}

func TestDrainClaimsSharedFixtureEventAliases(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	githubIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	slackIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
	githubFixture := readGitHubParityFixture(t)
	slackFixture := readSlackParityFixture(t)

	githubPayloadJSON, _ := json.Marshal(githubFixture.Positive.Payload.Payload)
	slackPayloadJSON, _ := json.Marshal(slackFixture.Positive.Payload.Payload)
	slackAliasPayloadJSON, _ := json.Marshal(slackFixture.Alias.Payload.Payload)

	githubJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: githubIntegrationID, provider: "GITHUB", eventType: githubFixture.Positive.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: githubPayloadJSON})
	slackJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: slackIntegrationID, provider: "SLACK", eventType: slackFixture.Positive.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: slackPayloadJSON})
	slackAliasJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: slackIntegrationID, provider: "SLACK", eventType: slackFixture.Alias.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: slackAliasPayloadJSON})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 10)
	restore()
	if err != nil {
		t.Fatalf("drain aliases: %v", err)
	}
	if result.Processed != 3 || result.Succeeded != 3 || result.Failed != 0 {
		t.Fatalf("unexpected alias drain result: %#v", result)
	}
	for _, jobID := range []string{githubJobID, slackJobID, slackAliasJobID} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("alias job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	var eventCount int
	var maxSeverity string
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*), MAX(severity::text)
		FROM ingested_events
		WHERE organization_id = $1
		  AND event_type IN ($2, $3, $4)
		  AND processing_status = 'PROCESSED'::"EventProcessingStatus"
	`, orgID, githubFixture.Positive.Payload.EventType, slackFixture.Positive.Payload.EventType, slackFixture.Alias.Payload.EventType).Scan(&eventCount, &maxSeverity); err != nil {
		t.Fatalf("query alias events: %v", err)
	}
	if eventCount != 3 || maxSeverity != "CRITICAL" {
		t.Fatalf("alias events = count=%d maxSeverity=%s", eventCount, maxSeverity)
	}

	githubPayload := githubFixture.Positive.Payload.jobPayload(t)
	githubPayload.OrganizationID = orgID
	githubPayload.IntegrationID = githubIntegrationID
	githubFinding := Evaluate(githubPayload, nil)[0]
	var githubFindingCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM security_findings
		WHERE organization_id = $1 AND integration_id = $2 AND dedupe_key = $3
	`, orgID, githubIntegrationID, DedupeKey(githubPayload, githubFinding)).Scan(&githubFindingCount); err != nil {
		t.Fatalf("count GitHub alias finding: %v", err)
	}
	if githubFindingCount != 1 {
		t.Fatalf("expected one GitHub alias finding, got %d", githubFindingCount)
	}

	events := decodeWideEvents(t, sink)
	successes := 0
	for _, event := range events {
		if event["outcome"] == "succeeded" {
			successes++
			if event["organization_id"] != orgID || event["provider"] == "" || event["event_type"] == "" || event["attempt"] != float64(1) || event["max_attempts"] != float64(3) {
				t.Fatalf("success telemetry missing required fields: %#v", event)
			}
		}
	}
	if successes != 3 || strings.Contains(sink.String(), "test-token") {
		t.Fatalf("unexpected alias telemetry successes=%d body=%s", successes, sink.String())
	}
}

func TestDrainPersistsSupportedSlackMFAJob(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")

	payloadMap := map[string]any{
		"user": map[string]any{
			"id":    "U123",
			"email": "user@example.com",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobPayload := JobPayload{
		OrganizationID: orgID,
		IntegrationID:  integrationID,
		Provider:       "SLACK",
		EventType:      "TWO_FACTOR_AUTH_DISABLED",
		Source:         "slack-audit-log",
		Actor:          "admin@example.com",
		OccurredAt:     time.Now().UTC().Add(-time.Minute),
		Payload:        payloadMap,
	}
	finding := Evaluate(jobPayload, nil)[0]
	dedupe := DedupeKey(jobPayload, finding)

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "TWO_FACTOR_AUTH_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, jobID)
		t.Fatalf("unexpected drain result: %#v lastError=%v", result, jobError)
	}

	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("supported Slack job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	successTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "succeeded")
	if successTelemetry["provider"] != "SLACK" || successTelemetry["event_type"] != "TWO_FACTOR_AUTH_DISABLED" || successTelemetry["attempt"] != float64(1) || successTelemetry["max_attempts"] != float64(3) {
		t.Fatalf("Slack success telemetry missing required fields: %#v", successTelemetry)
	}

	var eventID string
	var eventProvider, eventType string
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, provider::text, event_type
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, jobID, orgID).Scan(&eventID, &eventProvider, &eventType); err != nil {
		t.Fatalf("query Slack ingested event: %v", err)
	}
	if eventProvider != "SLACK" || eventType != "TWO_FACTOR_AUTH_DISABLED" {
		t.Fatalf("Slack event persisted as provider=%s event=%s", eventProvider, eventType)
	}

	var persistedFindingID, title, severity string
	var riskScore int
	var evidence map[string]any
	var rawEvidence json.RawMessage
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, title, severity::text, risk_score, evidence
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, dedupe).Scan(&persistedFindingID, &title, &severity, &riskScore, &rawEvidence); err != nil {
		t.Fatalf("query Slack security finding: %v", err)
	}
	if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
		t.Fatalf("decode Slack finding evidence: %v", err)
	}
	if persistedFindingID == "" || title != finding.Title || severity != finding.Severity || riskScore != finding.RiskScore {
		t.Fatalf("Slack finding fields = id=%s title=%s severity=%s risk=%d", persistedFindingID, title, severity, riskScore)
	}
	if evidence["ruleId"] != "slack.mfa_disabled" || evidence["user"] != "user@example.com" || evidence["sourceEventId"] != eventID {
		t.Fatalf("Slack finding evidence = %#v", evidence)
	}
}

func TestDrainProcessesSupportedSlackDisabledCheckWithoutFinding(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET disabled_checks = ARRAY['slack.mfa_disabled']::text[]
		WHERE id = $1
	`, integrationID); err != nil {
		t.Fatalf("disable Slack check: %v", err)
	}

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected disabled-check drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("disabled-check job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	disabledTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "succeeded")
	if disabledTelemetry["provider"] != "SLACK" || disabledTelemetry["event_type"] != "MFA_DISABLED" || disabledTelemetry["attempt"] != float64(1) {
		t.Fatalf("disabled-check telemetry missing required fields: %#v", disabledTelemetry)
	}

	var eventCount, findingCount int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1 AND ingestion_job_id = $2`, orgID, jobID).Scan(&eventCount); err != nil {
		t.Fatalf("count disabled-check events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1`, orgID).Scan(&findingCount); err != nil {
		t.Fatalf("count disabled-check findings: %v", err)
	}
	if eventCount != 1 || findingCount != 0 {
		t.Fatalf("disabled check should persist event only, got events=%d findings=%d", eventCount, findingCount)
	}
}

func TestSupportedSlackJobRequiresMatchingConnectedIntegration(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	githubIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: githubIntegrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected wrong-provider drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("wrong-provider job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	var eventCount, findingCount int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1`, orgID).Scan(&eventCount); err != nil {
		t.Fatalf("count wrong-provider events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1`, orgID).Scan(&findingCount); err != nil {
		t.Fatalf("count wrong-provider findings: %v", err)
	}
	if eventCount != 0 || findingCount != 0 {
		t.Fatalf("wrong-provider integration should not persist side effects, got events=%d findings=%d", eventCount, findingCount)
	}
}

func TestDrainPersistsSupportedGitHubJobSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'worker-side-effects.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/aperio",
			"name":       "aperio",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobPayload := JobPayload{
		OrganizationID: orgID,
		IntegrationID:  integrationID,
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "github-audit-log",
		Actor:          "admin@example.com",
		OccurredAt:     time.Now().UTC().Add(-time.Minute),
		Payload:        payloadMap,
	}
	finding := Evaluate(jobPayload, nil)[0]
	dedupe := DedupeKey(jobPayload, finding)
	findingID := testWorkerID("fnd")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at, resolved_at
		)
		VALUES (
			$1, $2, $3, $4, 'Old title', 'Old description', 'HIGH'::"Severity",
			'RESOLVED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 hour'
		)
	`, findingID, orgID, integrationID, dedupe); err != nil {
		t.Fatalf("seed resolved finding: %v", err)
	}

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	worker := &Worker{db: db, leaseOwner: "go-test-worker"}
	result, err := worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, jobID)
		t.Fatalf("unexpected drain result: %#v lastError=%v", result, jobError)
	}

	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("supported job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}

	var eventID string
	var eventStatus string
	var persistedEventSeverity string
	var eventOccurredAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, processing_status::text, severity::text, occurred_at
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, jobID, orgID).Scan(&eventID, &eventStatus, &persistedEventSeverity, &eventOccurredAt); err != nil {
		t.Fatalf("query ingested event: %v", err)
	}
	if eventStatus != "PROCESSED" || persistedEventSeverity != finding.Severity {
		t.Fatalf("event processing status/severity = %s/%s", eventStatus, persistedEventSeverity)
	}

	var persistedFindingID string
	var findingStatus string
	var resolvedAt sql.NullTime
	var eventIDOnFinding sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, status::text, resolved_at, event_id
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, dedupe).Scan(&persistedFindingID, &findingStatus, &resolvedAt, &eventIDOnFinding); err != nil {
		t.Fatalf("query security finding: %v", err)
	}
	if persistedFindingID != findingID || findingStatus != "OPEN" || resolvedAt.Valid || !eventIDOnFinding.Valid || eventIDOnFinding.String != eventID {
		t.Fatalf("finding dedupe/reopen state = id=%s status=%s resolved=%v event=%v", persistedFindingID, findingStatus, resolvedAt, eventIDOnFinding)
	}

	var lastSyncAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT last_sync_at
		FROM integration_connections
		WHERE id = $1
	`, integrationID).Scan(&lastSyncAt); err != nil {
		t.Fatalf("query integration last sync: %v", err)
	}
	if !lastSyncAt.Valid {
		t.Fatal("expected supported Go ingestion to update integration last_sync_at")
	}

	var deliveryPayload siemdispatcher.Payload
	var deliveryStatus, deliveryDedupe, deliveryStream, deliveryDestination string
	var rawDelivery json.RawMessage
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, dedupe_key, stream::text, destination_id, payload
		FROM siem_deliveries
		WHERE organization_id = $1
	`, orgID).Scan(&deliveryStatus, &deliveryDedupe, &deliveryStream, &deliveryDestination, &rawDelivery); err != nil {
		t.Fatalf("query SIEM delivery: %v", err)
	}
	if err := json.Unmarshal(rawDelivery, &deliveryPayload); err != nil {
		t.Fatalf("decode SIEM delivery payload: %v", err)
	}
	if deliveryStatus != "PENDING" || deliveryStream != "FINDINGS" || deliveryDestination != destinationID {
		t.Fatalf("delivery routing state = status=%s stream=%s destination=%s", deliveryStatus, deliveryStream, deliveryDestination)
	}
	assertFindingDeliveryPayload(t, deliveryPayload, findingDeliveryExpectation{
		orgID:            orgID,
		occurredAt:       eventOccurredAt,
		findingID:        persistedFindingID,
		dedupeKey:        dedupe,
		sourceEventID:    eventID,
		status:           findingStatus,
		finding:          finding,
		provider:         "GITHUB",
		integrationID:    integrationID,
		source:           "test",
		eventType:        "PUBLIC_REPOSITORY_CREATED",
		actor:            "worker@example.com",
		referenceRecord:  readSiemFindingDeliveryReferenceRecord(t),
		destinationID:    destinationID,
		deliveryDedupe:   deliveryDedupe,
		deliveryDedupeOf: "first observation",
	})
	if want := siemdispatcher.StableDeliveryKey(deliveryPayload, destinationID, "FINDINGS"); deliveryDedupe != want {
		t.Fatalf("delivery dedupe key = %s, want %s", deliveryDedupe, want)
	}

	secondJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	result, err = worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, secondJobID)
		t.Fatalf("unexpected second drain result: %#v lastError=%v", result, jobError)
	}

	var secondEventID string
	var secondEventOccurredAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, occurred_at
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, secondJobID, orgID).Scan(&secondEventID, &secondEventOccurredAt); err != nil {
		t.Fatalf("query second ingested event: %v", err)
	}
	if secondEventID == eventID {
		t.Fatalf("expected distinct persisted event ids for repeated observations, got %s", secondEventID)
	}

	var deliveryCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2 AND stream = 'FINDINGS'::"SiemStreamType"
	`, orgID, destinationID).Scan(&deliveryCount); err != nil {
		t.Fatalf("count SIEM deliveries: %v", err)
	}
	if deliveryCount != 2 {
		t.Fatalf("expected repeated observations to enqueue distinct deliveries, got %d", deliveryCount)
	}

	var secondRawDelivery json.RawMessage
	var secondDeliveryDedupe string
	if err := db.QueryRowContext(context.Background(), `
		SELECT dedupe_key, payload
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2 AND payload->'record'->>'sourceEventId' = $3
	`, orgID, destinationID, secondEventID).Scan(&secondDeliveryDedupe, &secondRawDelivery); err != nil {
		t.Fatalf("query second SIEM delivery: %v", err)
	}
	var secondDeliveryPayload siemdispatcher.Payload
	if err := json.Unmarshal(secondRawDelivery, &secondDeliveryPayload); err != nil {
		t.Fatalf("decode second SIEM delivery payload: %v", err)
	}
	assertFindingDeliveryPayload(t, secondDeliveryPayload, findingDeliveryExpectation{
		orgID:            orgID,
		occurredAt:       secondEventOccurredAt,
		findingID:        persistedFindingID,
		dedupeKey:        dedupe,
		sourceEventID:    secondEventID,
		status:           "OPEN",
		finding:          finding,
		provider:         "GITHUB",
		integrationID:    integrationID,
		source:           "test",
		eventType:        "PUBLIC_REPOSITORY_CREATED",
		actor:            "worker@example.com",
		referenceRecord:  readSiemFindingDeliveryReferenceRecord(t),
		destinationID:    destinationID,
		deliveryDedupe:   secondDeliveryDedupe,
		deliveryDedupeOf: "second observation",
	})
	if secondDeliveryDedupe == deliveryDedupe {
		t.Fatal("expected repeated observations with different sourceEventId values to have distinct delivery dedupe keys")
	}
}

func TestDrainPreservesMutedFindingsAndPublishesLifecycleAfterCommit(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")

	payloadForRepo := func(repo string) (json.RawMessage, JobPayload, Finding, string) {
		payloadMap := map[string]any{
			"repository": map[string]any{
				"full_name":  repo,
				"name":       repo[strings.LastIndex(repo, "/")+1:],
				"private":    false,
				"visibility": "public",
			},
		}
		payloadJSON, _ := json.Marshal(payloadMap)
		jobPayload := JobPayload{
			OrganizationID: orgID,
			IntegrationID:  integrationID,
			Provider:       "GITHUB",
			EventType:      "PUBLIC_REPOSITORY_CREATED",
			Source:         "github-audit-log",
			Actor:          "admin@example.com",
			OccurredAt:     time.Now().UTC().Add(-time.Minute),
			Payload:        payloadMap,
		}
		finding := Evaluate(jobPayload, nil)[0]
		return payloadJSON, jobPayload, finding, DedupeKey(jobPayload, finding)
	}

	resolvedPayloadJSON, _, resolvedFinding, resolvedDedupe := payloadForRepo("writer/resolved")
	mutedPayloadJSON, _, mutedFinding, mutedDedupe := payloadForRepo("writer/muted")
	resolvedFindingID := testWorkerID("fnd")
	mutedFindingID := testWorkerID("fnd")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at, resolved_at
		)
		VALUES
			($1, $2, $3, $4, $5, $6, 'HIGH'::"Severity", 'RESOLVED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 hour'),
			($7, $2, $3, $8, $9, $10, 'HIGH'::"Severity", 'MUTED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '2 hours')
	`, resolvedFindingID, orgID, integrationID, resolvedDedupe, resolvedFinding.Title, resolvedFinding.Description, mutedFindingID, mutedDedupe, mutedFinding.Title, mutedFinding.Description); err != nil {
		t.Fatalf("seed lifecycle findings: %v", err)
	}
	resolvedJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: resolvedPayloadJSON})
	mutedJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: mutedPayloadJSON})

	publisher := &recordingLifecyclePublisher{t: t, db: db}
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker", eventPublisher: publisher}).Drain(context.Background(), 2)
	if err != nil {
		t.Fatalf("drain lifecycle jobs: %v", err)
	}
	if result.Processed != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("unexpected lifecycle drain result: %#v", result)
	}
	for _, jobID := range []string{resolvedJobID, mutedJobID} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("lifecycle job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	var resolvedStatus string
	var resolvedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, resolved_at
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, resolvedFindingID, orgID).Scan(&resolvedStatus, &resolvedAt); err != nil {
		t.Fatalf("query resolved lifecycle finding: %v", err)
	}
	if resolvedStatus != "OPEN" || resolvedAt.Valid {
		t.Fatalf("resolved finding should reopen, got status=%s resolvedAt=%v", resolvedStatus, resolvedAt)
	}

	var mutedStatus string
	var mutedResolvedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, resolved_at
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, mutedFindingID, orgID).Scan(&mutedStatus, &mutedResolvedAt); err != nil {
		t.Fatalf("query muted lifecycle finding: %v", err)
	}
	if mutedStatus != "MUTED" || !mutedResolvedAt.Valid {
		t.Fatalf("muted finding should remain muted with resolved_at preserved, got status=%s resolvedAt=%v", mutedStatus, mutedResolvedAt)
	}

	if len(publisher.seen) != 1 {
		t.Fatalf("expected only reopened finding lifecycle event, got %#v", publisher.seen)
	}
	event := publisher.seen[0]
	if event.FindingID != resolvedFindingID || event.OrganizationID != orgID || event.IntegrationID != integrationID || event.PreviousStatus != "RESOLVED" || event.NextStatus != "OPEN" || event.ResolutionNote != "Finding observed again during ingestion" {
		t.Fatalf("unexpected lifecycle event: %#v", event)
	}
}

func TestDrainMaintainsTenantIsolationForFindingsEventsAndDeliveries(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgA := seedIngestionWorkerOrg(t, db)
	orgB := seedIngestionWorkerOrg(t, db)
	integrationA := seedIngestionWorkerIntegration(t, db, orgA, "GITHUB", "CONNECTED")
	integrationB := seedIngestionWorkerIntegration(t, db, orgB, "GITHUB", "CONNECTED")
	destinationA := testWorkerID("dst")
	destinationB := testWorkerID("dst")
	for _, row := range []struct {
		id    string
		orgID string
	}{
		{id: destinationA, orgID: orgA},
		{id: destinationB, orgID: orgB},
	} {
		if _, err := db.ExecContext(context.Background(), `
			INSERT INTO siem_destinations (
				id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
			)
			VALUES (
				$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'tenant-isolation.jsonl',
				ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
			)
		`, row.id, row.orgID); err != nil {
			t.Fatalf("seed tenant SIEM destination: %v", err)
		}
	}

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/shared",
			"name":       "shared",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobA := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgA, integrationID: integrationA, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})
	jobB := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgB, integrationID: integrationB, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 2)
	if err != nil {
		t.Fatalf("drain tenant jobs: %v", err)
	}
	if result.Processed != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("unexpected tenant drain result: %#v", result)
	}
	for _, jobID := range []string{jobA, jobB} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("tenant job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	for _, row := range []struct {
		orgID         string
		integrationID string
		destinationID string
	}{
		{orgID: orgA, integrationID: integrationA, destinationID: destinationA},
		{orgID: orgB, integrationID: integrationB, destinationID: destinationB},
	} {
		jobPayload := JobPayload{
			OrganizationID: row.orgID,
			IntegrationID:  row.integrationID,
			Provider:       "GITHUB",
			EventType:      "PUBLIC_REPOSITORY_CREATED",
			Source:         "test",
			Actor:          "worker@example.com",
			OccurredAt:     time.Now().UTC(),
			Payload:        payloadMap,
		}
		finding := Evaluate(jobPayload, nil)[0]
		dedupe := DedupeKey(jobPayload, finding)
		var findingCount, eventCount, deliveryCount, mismatchedDeliveries int
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM security_findings WHERE organization_id = $1 AND integration_id = $2 AND dedupe_key = $3
		`, row.orgID, row.integrationID, dedupe).Scan(&findingCount); err != nil {
			t.Fatalf("count tenant finding: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1 AND integration_id = $2
		`, row.orgID, row.integrationID).Scan(&eventCount); err != nil {
			t.Fatalf("count tenant event: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1 AND destination_id = $2
		`, row.orgID, row.destinationID).Scan(&deliveryCount); err != nil {
			t.Fatalf("count tenant delivery: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*)
			FROM siem_deliveries sd
			JOIN siem_destinations dst ON dst.id = sd.destination_id
			WHERE sd.organization_id = $1 AND dst.organization_id <> sd.organization_id
		`, row.orgID).Scan(&mismatchedDeliveries); err != nil {
			t.Fatalf("count mismatched tenant deliveries: %v", err)
		}
		if findingCount != 1 || eventCount != 1 || deliveryCount != 1 || mismatchedDeliveries != 0 {
			t.Fatalf("tenant %s counts finding=%d event=%d delivery=%d mismatched=%d", row.orgID, findingCount, eventCount, deliveryCount, mismatchedDeliveries)
		}
	}
}

type findingDeliveryExpectation struct {
	orgID            string
	occurredAt       time.Time
	findingID        string
	dedupeKey        string
	sourceEventID    string
	status           string
	finding          Finding
	provider         string
	integrationID    string
	source           string
	eventType        string
	actor            string
	referenceRecord  map[string]any
	destinationID    string
	deliveryDedupe   string
	deliveryDedupeOf string
}

func assertFindingDeliveryPayload(t *testing.T, payload siemdispatcher.Payload, want findingDeliveryExpectation) {
	t.Helper()
	if payload.Kind != "finding" || payload.OrganizationID != want.orgID {
		t.Fatalf("delivery payload routing = kind=%s org=%s", payload.Kind, payload.OrganizationID)
	}
	if payload.OccurredAt != want.occurredAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("delivery occurredAt = %s, want %s", payload.OccurredAt, want.occurredAt.UTC().Format(time.RFC3339Nano))
	}
	for key := range want.referenceRecord {
		if _, ok := payload.Record[key]; !ok {
			t.Fatalf("delivery record missing shared fixture field %q in %#v", key, payload.Record)
		}
	}
	requireRecordString(t, payload.Record, "schemaVersion", "aperio.finding.v1")
	requireRecordString(t, payload.Record, "findingId", want.findingID)
	requireRecordString(t, payload.Record, "dedupeKey", want.dedupeKey)
	requireRecordString(t, payload.Record, "sourceEventId", want.sourceEventID)
	requireRecordString(t, payload.Record, "status", want.status)
	requireRecordString(t, payload.Record, "ruleId", want.finding.RuleID)
	requireRecordString(t, payload.Record, "title", want.finding.Title)
	requireRecordString(t, payload.Record, "description", want.finding.Description)
	requireRecordString(t, payload.Record, "severity", want.finding.Severity)
	requireRecordNumber(t, payload.Record, "riskScore", float64(want.finding.RiskScore))
	requireRecordStringSlice(t, payload.Record, "remediationSteps", want.finding.RemediationSteps)
	requireRecordString(t, payload.Record, "target", want.finding.Target)
	requireRecordString(t, payload.Record, "provider", want.provider)
	requireRecordString(t, payload.Record, "integrationId", want.integrationID)
	requireRecordString(t, payload.Record, "source", want.source)
	requireRecordString(t, payload.Record, "eventType", want.eventType)
	requireRecordString(t, payload.Record, "actor", want.actor)
	if got, wantKey := want.deliveryDedupe, siemdispatcher.StableDeliveryKey(payload, want.destinationID, "FINDINGS"); got != wantKey {
		t.Fatalf("%s delivery dedupe key = %s, want %s", want.deliveryDedupeOf, got, wantKey)
	}
}

func requireRecordString(t *testing.T, record map[string]any, key string, want string) {
	t.Helper()
	got, ok := record[key].(string)
	if !ok || got != want {
		t.Fatalf("delivery record[%s] = %#v, want %q", key, record[key], want)
	}
}

func requireRecordNumber(t *testing.T, record map[string]any, key string, want float64) {
	t.Helper()
	got, ok := record[key].(float64)
	if !ok || got != want {
		t.Fatalf("delivery record[%s] = %#v, want %v", key, record[key], want)
	}
}

func requireRecordStringSlice(t *testing.T, record map[string]any, key string, want []string) {
	t.Helper()
	values, ok := record[key].([]any)
	if !ok || len(values) != len(want) {
		t.Fatalf("delivery record[%s] = %#v, want %#v", key, record[key], want)
	}
	for index, value := range values {
		got, ok := value.(string)
		if !ok || got != want[index] {
			t.Fatalf("delivery record[%s][%d] = %#v, want %q", key, index, value, want[index])
		}
	}
}

func TestDrainRetriesExpiredLeasesAndHonorsLimit(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	disabledIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "DISABLED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/aperio","visibility":"public"}}`)
	firstJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: disabledIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})
	secondJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: disabledIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain retryable failure: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected retryable failure result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, firstJobID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("retryable failure state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	if !ingestionJobNextAttemptAt(t, db, firstJobID).After(time.Now().UTC()) {
		t.Fatal("retryable failure should schedule a future next_attempt_at")
	}
	status, attempts, leaseOwner, processedAt, lastError = ingestionJobState(t, db, secondJobID)
	if status != "QUEUED" || attempts != 0 || leaseOwner.Valid || processedAt.Valid || lastError.Valid {
		t.Fatalf("limit should leave second job untouched, got status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	failedTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "failed")
	if failedTelemetry["provider"] != "GITHUB" || failedTelemetry["event_type"] != "PUBLIC_REPOSITORY_CREATED" || failedTelemetry["attempt"] != float64(1) || failedTelemetry["max_attempts"] != float64(3) || failedTelemetry["error_kind"] != "error" {
		t.Fatalf("retry telemetry missing required fields: %#v", failedTelemetry)
	}
	if strings.Contains(sink.String(), "test-token") {
		t.Fatalf("retry telemetry leaked integration token: %s", sink.String())
	}

	if _, err := db.ExecContext(context.Background(), `
		UPDATE ingestion_jobs SET next_attempt_at = NOW() + INTERVAL '1 hour' WHERE id = $1
	`, secondJobID); err != nil {
		t.Fatalf("defer second retry job: %v", err)
	}
	connectedIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	staleOwner := "stale-worker"
	expiredJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: connectedIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "RUNNING", attempts: 0, maxAttempts: 3, leaseOwner: &staleOwner, payload: payload})
	result, err = (&Worker{db: db, leaseOwner: "reclaim-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain expired lease: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected expired lease result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError = ingestionJobState(t, db, expiredJobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("expired lease job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
}

func TestDrainConcurrentWorkersDoNotDuplicateClaims(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/concurrent","visibility":"public"}}`)
	for i := 0; i < 4; i++ {
		seedIngestionWorkerJob(t, db, struct {
			orgID         string
			integrationID string
			provider      string
			eventType     string
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
			payload       json.RawMessage
		}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan Result, 2)
	errs := make(chan error, 2)
	for _, owner := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			<-start
			result, err := (&Worker{db: db, leaseOwner: owner}).Drain(context.Background(), 3)
			results <- result
			errs <- err
		}(owner)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent drain: %v", err)
		}
	}
	totalProcessed := 0
	totalSucceeded := 0
	for result := range results {
		totalProcessed += result.Processed
		totalSucceeded += result.Succeeded
	}
	if totalProcessed != 4 || totalSucceeded != 4 {
		t.Fatalf("expected four unique jobs processed, got processed=%d succeeded=%d", totalProcessed, totalSucceeded)
	}

	var eventCount, succeededJobs int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1
	`, orgID).Scan(&eventCount); err != nil {
		t.Fatalf("count concurrent ingested events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM ingestion_jobs WHERE organization_id = $1 AND status = 'SUCCEEDED'::"IngestionJobStatus"
	`, orgID).Scan(&succeededJobs); err != nil {
		t.Fatalf("count concurrent succeeded jobs: %v", err)
	}
	if eventCount != 4 || succeededJobs != 4 {
		t.Fatalf("concurrent workers should process each job once, events=%d succeededJobs=%d", eventCount, succeededJobs)
	}
}

func TestSupportedIngestionFailureDeadLettersAndHonorsLease(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "DISABLED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/aperio","visibility":"public"}}`)
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 2, maxAttempts: 3, payload: payload})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "DEAD_LETTER" || attempts != 3 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("dead-letter state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	deadTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "dead_letter")
	if deadTelemetry["provider"] != "GITHUB" || deadTelemetry["attempt"] != float64(3) || deadTelemetry["max_attempts"] != float64(3) || deadTelemetry["error_kind"] != "error" {
		t.Fatalf("dead-letter telemetry missing required fields: %#v", deadTelemetry)
	}

	otherOwner := "other-worker"
	lostLeaseJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "RUNNING", attempts: 0, maxAttempts: 3, leaseOwner: &otherOwner, payload: payload})
	err = (&Worker{db: db, leaseOwner: "go-test-worker"}).finish(context.Background(), job{
		ID:          lostLeaseJobID,
		Attempts:    0,
		MaxAttempts: 3,
	}, false, "lost lease probe")
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("expected lost lease error, got %v", err)
	}
	status, attempts, leaseOwner, _, _ = ingestionJobState(t, db, lostLeaseJobID)
	if status != "RUNNING" || attempts != 0 || !leaseOwner.Valid || leaseOwner.String != otherOwner {
		t.Fatalf("lost lease job changed: status=%s attempts=%d lease=%v", status, attempts, leaseOwner)
	}
}
