package ingestionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/siemdispatcher"
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

func TestDrainLeavesUnsupportedIngestionJobsUntouched(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")

	queuedID := seedIngestionWorkerJob(t, db, struct {
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

	exhaustedID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "FAILED", attempts: 3, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 0 || result.Succeeded != 0 || result.Failed != 0 {
		t.Fatalf("expected unsupported jobs to remain unprocessed, got %#v", result)
	}

	status, attempts, leaseOwner, processedAt, _ := ingestionJobState(t, db, queuedID)
	if status != "QUEUED" || attempts != 0 || leaseOwner.Valid || processedAt.Valid {
		t.Fatalf("unsupported queued job changed: status=%s attempts=%d lease=%v processed=%v", status, attempts, leaseOwner, processedAt)
	}

	status, attempts, leaseOwner, processedAt, _ = ingestionJobState(t, db, exhaustedID)
	if status != "FAILED" || attempts != 3 || leaseOwner.Valid || processedAt.Valid {
		t.Fatalf("unsupported exhausted job changed: status=%s attempts=%d lease=%v processed=%v", status, attempts, leaseOwner, processedAt)
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
	var eventOccurredAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, processing_status::text, occurred_at
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, jobID, orgID).Scan(&eventID, &eventStatus, &eventOccurredAt); err != nil {
		t.Fatalf("query ingested event: %v", err)
	}
	if eventStatus != "PROCESSED" {
		t.Fatalf("event processing status = %s", eventStatus)
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

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
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
