package ingestionworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/aperio/internal/siemdispatcher"
	"github.com/writer/aperio/internal/telemetry"
)

const leaseDuration = 5 * time.Minute

var errIngestionLeaseLost = errors.New("ingestion job lease lost")

type JobPayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor,omitempty"`
	OccurredAt     time.Time      `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

type Finding struct {
	RuleID           string
	Title            string
	Description      string
	Severity         string
	RiskScore        int
	RemediationSteps []string
	Target           string
	Evidence         map[string]any
}

type persistedFinding struct {
	ID             string
	Status         string
	PreviousStatus string
}

type Result struct {
	Processed int
	Succeeded int
	Failed    int
}

type Worker struct {
	db             *sql.DB
	leaseOwner     string
	eventPublisher IngestionEventPublisher
}

type FindingLifecycleEvent struct {
	FindingID      string
	OrganizationID string
	IntegrationID  string
	PreviousStatus string
	NextStatus     string
	OccurredAt     time.Time
	ResolutionNote string
}

type IngestionEventPublisher interface {
	PublishFindingLifecycle(context.Context, FindingLifecycleEvent) error
}

type noopIngestionEventPublisher struct{}

func (noopIngestionEventPublisher) PublishFindingLifecycle(context.Context, FindingLifecycleEvent) error {
	return nil
}

type job struct {
	ID             string
	OrganizationID string
	IntegrationID  string
	Provider       string
	EventType      string
	Source         string
	Actor          sql.NullString
	OccurredAt     time.Time
	Payload        json.RawMessage
	Attempts       int
	MaxAttempts    int
}

func New(db *sql.DB) *Worker {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	return &Worker{
		db:             db,
		leaseOwner:     fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), randomID()),
		eventPublisher: noopIngestionEventPublisher{},
	}
}

func Evaluate(payload JobPayload, disabledChecks []string) []Finding {
	disabled := map[string]struct{}{}
	for _, check := range disabledChecks {
		disabled[check] = struct{}{}
	}
	findings := []Finding{}
	if _, ok := disabled["github.public_repository_created"]; !ok {
		if finding, ok := evaluateGitHubPublicRepository(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["slack.mfa_disabled"]; !ok {
		if finding, ok := evaluateSlackMFADisabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func evaluateGitHubPublicRepository(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GITHUB" {
		return Finding{}, false
	}
	normalized := normalizeEventType(payload.EventType)
	private, hasPrivate := nestedBool(payload.Payload, "repository", "private")
	visibility := nestedString(payload.Payload, "repository", "visibility")
	if normalized != "PUBLIC_REPOSITORY_CREATED" && (!hasPrivate || private) && visibility != "public" {
		return Finding{}, false
	}
	repository := firstNonEmpty(
		nestedString(payload.Payload, "repository", "full_name"),
		nestedString(payload.Payload, "repository", "name"),
		"unknown repository",
	)
	return Finding{
		RuleID:      "github.public_repository_created",
		Title:       "Public GitHub repository created",
		Description: "A repository was created or changed to public visibility, which can expose source code, secrets, or customer data.",
		Severity:    "CRITICAL",
		RiskScore:   95,
		RemediationSteps: []string{
			"Confirm the repository is approved for public release.",
			"Set repository visibility to private if public access is not explicitly authorized.",
			"Run secret scanning and branch protection checks before allowing continued public access.",
		},
		Target: repository,
		Evidence: map[string]any{
			"repository": repository,
			"subject":    repository,
			"visibility": firstNonEmpty(visibility, "public"),
		},
	}, true
}

func evaluateSlackMFADisabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SLACK" {
		return Finding{}, false
	}
	normalized := normalizeEventType(payload.EventType)
	if normalized != "MFA_DISABLED" && normalized != "TWO_FACTOR_AUTH_DISABLED" {
		return Finding{}, false
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "user", "email"),
		nestedString(payload.Payload, "user", "id"),
		payload.Actor,
		"unknown user",
	)
	return Finding{
		RuleID:      "slack.mfa_disabled",
		Title:       "Slack multi-factor authentication disabled",
		Description: "A Slack user disabled MFA, increasing the likelihood of account takeover and lateral movement.",
		Severity:    "CRITICAL",
		RiskScore:   90,
		RemediationSteps: []string{
			"Re-enable MFA for the affected Slack user immediately.",
			"Force a session reset for the affected account.",
			"Review recent login history and connected Slack apps for suspicious activity.",
		},
		Target: user,
		Evidence: map[string]any{
			"user":    user,
			"subject": user,
		},
	}, true
}

func DedupeKey(payload JobPayload, finding Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		payload.OrganizationID,
		payload.IntegrationID,
		finding.RuleID,
		finding.Target,
	}, ":")))
	return hex.EncodeToString(sum[:])
}

func (w *Worker) Drain(ctx context.Context, limit int) (Result, error) {
	if w.db == nil {
		return Result{}, errors.New("database is required")
	}
	limit = boundedLimit(limit)
	if err := w.retireExhausted(ctx); err != nil {
		return Result{}, err
	}
	jobs, err := w.claim(ctx, limit)
	if err != nil {
		return Result{}, err
	}
	result := Result{Processed: len(jobs)}
	for _, item := range jobs {
		startedAt := time.Now()
		err := w.process(ctx, item)
		emitIngestionJobWideEvent(item, err, time.Since(startedAt))
		if err != nil {
			result.Failed++
		} else {
			result.Succeeded++
		}
	}
	return result, nil
}

func (w *Worker) retireExhausted(ctx context.Context) error {
	_, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'DEAD_LETTER', lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW()
		WHERE attempts >= max_attempts
		  AND (
				(provider = 'GITHUB' AND event_type IN ('PUBLIC_REPOSITORY_CREATED', 'repository.publicized'))
			 OR (provider = 'SLACK' AND event_type IN ('MFA_DISABLED', 'TWO_FACTOR_AUTH_DISABLED', 'mfa.disabled', 'two-factor auth disabled'))
		  )
		  AND status IN ('QUEUED', 'FAILED', 'RUNNING')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
	`)
	return err
}

func (w *Worker) claim(ctx context.Context, limit int) ([]job, error) {
	rows, err := w.db.QueryContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'RUNNING', lease_owner = $1, lease_expires_at = $2, updated_at = NOW()
		WHERE id IN (
			SELECT id
			FROM ingestion_jobs
			WHERE attempts < max_attempts
			  AND next_attempt_at <= NOW()
			  AND (
					(provider = 'GITHUB' AND event_type IN ('PUBLIC_REPOSITORY_CREATED', 'repository.publicized'))
				 OR (provider = 'SLACK' AND event_type IN ('MFA_DISABLED', 'TWO_FACTOR_AUTH_DISABLED', 'mfa.disabled', 'two-factor auth disabled'))
			  )
			  AND (
					(status IN ('QUEUED', 'FAILED') AND (lease_expires_at IS NULL OR lease_expires_at <= NOW()))
				 OR (status = 'RUNNING' AND lease_expires_at <= NOW())
			  )
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, integration_id, provider::text, event_type, source, actor, occurred_at, payload, attempts, max_attempts
	`, w.leaseOwner, time.Now().UTC().Add(leaseDuration), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []job{}
	for rows.Next() {
		var item job
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.IntegrationID, &item.Provider, &item.EventType, &item.Source, &item.Actor, &item.OccurredAt, &item.Payload, &item.Attempts, &item.MaxAttempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, item)
	}
	return jobs, rows.Err()
}

func (w *Worker) process(ctx context.Context, item job) error {
	payload, err := item.toPayload()
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("parse payload: %w", err).Error())
	}
	findings, err := w.findingsForJob(ctx, payload, item)
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("load findings: %w", err).Error())
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("begin transaction: %w", err).Error())
	}
	txDone := false
	defer func() {
		if !txDone {
			_ = tx.Rollback()
		}
	}()
	fail := func(err error) error {
		txDone = true
		_ = tx.Rollback()
		return w.fail(ctx, item, err.Error())
	}
	lifecycleEvents := []FindingLifecycleEvent{}
	eventID := "evt_" + randomID()
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO ingested_events (id, organization_id, integration_id, ingestion_job_id, provider, event_type, source, actor, severity, payload, processing_status, occurred_at, processed_at, created_at)
		VALUES ($1,$2,$3,$4,$5::"SaaSProvider",$6,$7,$8,'INFO'::"Severity",$9::jsonb,'RECEIVED'::"EventProcessingStatus",$10,NULL,NOW())
		ON CONFLICT (ingestion_job_id) DO UPDATE SET payload = EXCLUDED.payload, processing_status = 'RECEIVED'::"EventProcessingStatus", processed_at = NULL, severity = 'INFO'::"Severity"
		RETURNING id
	`, eventID, item.OrganizationID, item.IntegrationID, item.ID, item.Provider, item.EventType, item.Source, nullableString(item.Actor), string(item.Payload), item.OccurredAt).Scan(&eventID); err != nil {
		return fail(fmt.Errorf("upsert ingested event: %w", err))
	}
	for _, finding := range findings {
		persisted, err := upsertFinding(ctx, tx, payload, finding, eventID)
		if err != nil {
			return fail(fmt.Errorf("upsert finding: %w", err))
		}
		if err := enqueueFindingDelivery(ctx, tx, payload, finding, eventID, persisted); err != nil {
			return fail(fmt.Errorf("enqueue SIEM delivery: %w", err))
		}
		if shouldPublishFindingLifecycle(persisted) {
			lifecycleEvents = append(lifecycleEvents, FindingLifecycleEvent{
				FindingID:      persisted.ID,
				OrganizationID: payload.OrganizationID,
				IntegrationID:  payload.IntegrationID,
				PreviousStatus: persisted.PreviousStatus,
				NextStatus:     persisted.Status,
				OccurredAt:     payload.OccurredAt,
				ResolutionNote: lifecycleResolutionNote(persisted),
			})
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE ingested_events
		SET severity = $2::"Severity", processing_status = 'PROCESSED'::"EventProcessingStatus", processed_at = NOW()
		WHERE id = $1 AND organization_id = $3
	`, eventID, eventSeverity(findings), item.OrganizationID); err != nil {
		return fail(fmt.Errorf("finalize ingested event: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE integration_connections
		SET last_sync_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, item.IntegrationID, item.OrganizationID); err != nil {
		return fail(fmt.Errorf("update integration last sync: %w", err))
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_owner = $2
	`, item.ID, w.leaseOwner)
	if err != nil {
		return fail(fmt.Errorf("mark job succeeded: %w", err))
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		txDone = true
		_ = tx.Rollback()
		return errIngestionLeaseLost
	}
	if err := tx.Commit(); err != nil {
		txDone = true
		return w.fail(ctx, item, fmt.Errorf("commit transaction: %w", err).Error())
	}
	txDone = true
	w.publishFindingLifecycleEvents(ctx, lifecycleEvents)
	return nil
}

func (w *Worker) fail(ctx context.Context, item job, message string) error {
	if err := w.finish(ctx, item, false, message); err != nil {
		return err
	}
	return errors.New(message)
}

func (w *Worker) findingsForJob(ctx context.Context, payload JobPayload, item job) ([]Finding, error) {
	disabledChecks, err := w.loadDisabledChecks(ctx, item)
	if err != nil {
		return nil, err
	}
	return Evaluate(payload, disabledChecks), nil
}

func (w *Worker) loadDisabledChecks(ctx context.Context, item job) ([]string, error) {
	var raw string
	if err := w.db.QueryRowContext(ctx, `
		SELECT COALESCE(array_to_json(disabled_checks)::text, '[]')
		FROM integration_connections
		WHERE id = $1 AND organization_id = $2 AND provider = $3::"SaaSProvider" AND status = 'CONNECTED'
	`, item.IntegrationID, item.OrganizationID, item.Provider).Scan(&raw); err != nil {
		return nil, err
	}
	disabledChecks := []string{}
	if err := json.Unmarshal([]byte(raw), &disabledChecks); err != nil {
		return nil, err
	}
	return disabledChecks, nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding, eventID string) (persistedFinding, error) {
	dedupe := DedupeKey(payload, finding)
	previousStatus := "NEW"
	var existingStatus string
	err := tx.QueryRowContext(ctx, `
		SELECT status::text
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, payload.OrganizationID, dedupe).Scan(&existingStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return persistedFinding{}, err
	}
	if err == nil {
		previousStatus = existingStatus
	}
	evidence := buildFindingEvidence(payload, finding, eventID)
	evidenceJSON, _ := json.Marshal(evidence)
	persisted := persistedFinding{PreviousStatus: previousStatus}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO security_findings (
			id, organization_id, integration_id, event_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::"Severity",'OPEN'::"FindingStatus",$9,$10::text[],$11::jsonb,$12)
		ON CONFLICT (organization_id, dedupe_key) DO UPDATE SET
			event_id = EXCLUDED.event_id,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			status = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN 'MUTED'::"FindingStatus" ELSE 'OPEN'::"FindingStatus" END,
			resolved_at = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN security_findings.resolved_at ELSE NULL END,
			resolved_by_id = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN security_findings.resolved_by_id ELSE NULL END,
			risk_score = EXCLUDED.risk_score,
			remediation_steps = EXCLUDED.remediation_steps,
			evidence = EXCLUDED.evidence
		RETURNING id, status::text
	`, "fnd_"+randomID(), payload.OrganizationID, payload.IntegrationID, eventID, dedupe, finding.Title, finding.Description, finding.Severity, finding.RiskScore, postgresTextArray(finding.RemediationSteps), string(evidenceJSON), payload.OccurredAt).Scan(&persisted.ID, &persisted.Status)
	return persisted, err
}

func buildFindingEvidence(payload JobPayload, finding Finding, eventID string) map[string]any {
	evidence := map[string]any{
		"ruleId":        finding.RuleID,
		"target":        finding.Target,
		"subject":       finding.Target,
		"provider":      payload.Provider,
		"source":        payload.Source,
		"eventType":     payload.EventType,
		"sourceEventId": eventID,
	}
	addNonEmptyEvidence(evidence, "actor", payload.Actor)
	addNonEmptyEvidence(evidence, "application", nestedString(payload.Payload, "application"))
	addNonEmptyEvidence(evidence, "sourceIp", nestedString(payload.Payload, "ipAddress"))
	for key, value := range finding.Evidence {
		if value != nil {
			evidence[key] = value
		}
	}
	return evidence
}

func addNonEmptyEvidence(evidence map[string]any, key string, value string) {
	if strings.TrimSpace(value) != "" {
		evidence[key] = strings.TrimSpace(value)
	}
}

func eventSeverity(findings []Finding) string {
	for _, finding := range findings {
		if finding.Severity == "CRITICAL" {
			return "CRITICAL"
		}
	}
	if len(findings) > 0 && strings.TrimSpace(findings[0].Severity) != "" {
		return findings[0].Severity
	}
	return "INFO"
}

func shouldPublishFindingLifecycle(finding persistedFinding) bool {
	return finding.PreviousStatus == "NEW" || (finding.PreviousStatus != "" && finding.PreviousStatus != finding.Status)
}

func lifecycleResolutionNote(finding persistedFinding) string {
	if finding.PreviousStatus == "RESOLVED" && finding.Status == "OPEN" {
		return "Finding observed again during ingestion"
	}
	return "Finding observed during ingestion"
}

func (w *Worker) publisher() IngestionEventPublisher {
	if w.eventPublisher != nil {
		return w.eventPublisher
	}
	return noopIngestionEventPublisher{}
}

func (w *Worker) publishFindingLifecycleEvents(ctx context.Context, events []FindingLifecycleEvent) {
	if len(events) == 0 {
		return
	}
	publisher := w.publisher()
	for _, event := range events {
		_ = publisher.PublishFindingLifecycle(ctx, event)
	}
}

func postgresTextArray(values []string) string {
	var builder strings.Builder
	builder.WriteByte('{')
	for index, value := range values {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('"')
		for _, char := range value {
			if char == '\\' || char == '"' {
				builder.WriteByte('\\')
			}
			builder.WriteRune(char)
		}
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func enqueueFindingDelivery(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding, eventID string, persisted persistedFinding) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id
		FROM siem_destinations
		WHERE organization_id = $1 AND status IN ('ACTIVE', 'ERROR') AND 'FINDINGS' = ANY(streams)
	`, payload.OrganizationID)
	if err != nil {
		return err
	}
	destinationIDs := []string{}
	for rows.Next() {
		var destinationID string
		if err := rows.Scan(&destinationID); err != nil {
			_ = rows.Close()
			return err
		}
		destinationIDs = append(destinationIDs, destinationID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	dedupe := DedupeKey(payload, finding)
	status := persisted.Status
	if status == "" {
		status = "OPEN"
	}
	var actor any
	if payload.Actor != "" {
		actor = payload.Actor
	}
	for _, destinationID := range destinationIDs {
		record := map[string]any{
			"schemaVersion":    "aperio.finding.v1",
			"findingId":        persisted.ID,
			"dedupeKey":        dedupe,
			"sourceEventId":    eventID,
			"status":           status,
			"ruleId":           finding.RuleID,
			"title":            finding.Title,
			"description":      finding.Description,
			"severity":         finding.Severity,
			"riskScore":        finding.RiskScore,
			"remediationSteps": finding.RemediationSteps,
			"target":           finding.Target,
			"provider":         payload.Provider,
			"integrationId":    payload.IntegrationID,
			"source":           payload.Source,
			"eventType":        payload.EventType,
			"actor":            actor,
		}
		deliveryPayload := siemdispatcher.Payload{
			Kind:           "finding",
			OrganizationID: payload.OrganizationID,
			OccurredAt:     payload.OccurredAt.UTC().Format(time.RFC3339Nano),
			Record:         record,
		}
		payloadJSON, _ := json.Marshal(deliveryPayload)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO siem_deliveries (id, organization_id, destination_id, stream, dedupe_key, payload, created_at, updated_at)
			VALUES ($1,$2,$3,'FINDINGS'::"SiemStreamType",$4,$5::jsonb,NOW(),NOW())
			ON CONFLICT (organization_id, destination_id, stream, dedupe_key) DO NOTHING
		`, "sdel_"+randomID(), payload.OrganizationID, destinationID, siemdispatcher.StableDeliveryKey(deliveryPayload, destinationID, "FINDINGS"), string(payloadJSON))
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) finish(ctx context.Context, item job, ok bool, message string) error {
	if ok {
		res, err := w.db.ExecContext(ctx, `
			UPDATE ingestion_jobs
			SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $1 AND lease_owner = $2
		`, item.ID, w.leaseOwner)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil && rows != 1 {
			return errIngestionLeaseLost
		}
		return nil
	}
	attempts := item.Attempts + 1
	status := "FAILED"
	if attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	res, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6
	`, status, attempts, time.Now().UTC().Add(nextRetryDelay(attempts)), truncate(message, 500), item.ID, w.leaseOwner)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		return errIngestionLeaseLost
	}
	return nil
}

func (j job) toPayload() (JobPayload, error) {
	var record map[string]any
	if err := json.Unmarshal(j.Payload, &record); err != nil {
		return JobPayload{}, err
	}
	return JobPayload{
		OrganizationID: j.OrganizationID,
		IntegrationID:  j.IntegrationID,
		Provider:       j.Provider,
		EventType:      j.EventType,
		Source:         j.Source,
		Actor:          nullableString(j.Actor),
		OccurredAt:     j.OccurredAt,
		Payload:        record,
	}, nil
}

func normalizeEventType(value string) string {
	var builder strings.Builder
	lastWasSeparator := false
	for _, char := range strings.ToUpper(value) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
			lastWasSeparator = false
			continue
		}
		if !lastWasSeparator {
			builder.WriteByte('_')
			lastWasSeparator = true
		}
	}
	return builder.String()
}

func nestedString(value map[string]any, path ...string) string {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[segment]
	}
	text, _ := current.(string)
	return strings.TrimSpace(text)
}

func nestedBool(value map[string]any, path ...string) (bool, bool) {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return false, false
		}
		current = next[segment]
	}
	result, ok := current.(bool)
	return result, ok
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nullableString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func boundedLimit(limit int) int {
	if limit < 1 {
		return 25
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func emitIngestionJobWideEvent(item job, processErr error, duration time.Duration) {
	telemetry.EmitWide(ingestionJobWideEvent(item, processErr, duration))
}

func ingestionJobWideEvent(item job, processErr error, duration time.Duration) telemetry.WideEvent {
	dimensions := map[string]string{
		"outcome":    ingestionJobOutcome(item, processErr),
		"provider":   item.Provider,
		"event_type": item.EventType,
	}
	if kind := ingestionErrorKind(processErr); kind != "" {
		dimensions["error_kind"] = kind
	}
	return telemetry.WideEvent{
		Name:         "ingestion.job.process",
		Service:      "ingestion-worker",
		Organization: item.OrganizationID,
		Dimensions:   dimensions,
		Measurements: map[string]int64{
			"attempt":      int64(item.Attempts + 1),
			"max_attempts": int64(item.MaxAttempts),
			"duration_ms":  duration.Milliseconds(),
		},
	}
}

func ingestionJobOutcome(item job, processErr error) string {
	if processErr == nil {
		return "succeeded"
	}
	if errors.Is(processErr, errIngestionLeaseLost) {
		return "lost_lease"
	}
	if item.Attempts+1 >= item.MaxAttempts {
		return "dead_letter"
	}
	return "failed"
}

func ingestionErrorKind(processErr error) string {
	if processErr == nil {
		return ""
	}
	if errors.Is(processErr, errIngestionLeaseLost) {
		return "lease_lost"
	}
	return "error"
}

func nextRetryDelay(attempt int) time.Duration {
	delay := 30 * time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return delay
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func randomID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
