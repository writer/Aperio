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
)

const leaseDuration = 5 * time.Minute

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

type Result struct {
	Processed int
	Succeeded int
	Failed    int
}

type Worker struct {
	db         *sql.DB
	leaseOwner string
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
	return &Worker{db: db, leaseOwner: fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), randomID())}
}

func Evaluate(payload JobPayload, disabledChecks []string) []Finding {
	disabled := map[string]struct{}{}
	for _, check := range disabledChecks {
		disabled[check] = struct{}{}
	}
	if _, ok := disabled["github.public_repository_created"]; ok {
		return nil
	}
	if payload.Provider != "GITHUB" {
		return nil
	}
	normalized := normalizeEventType(payload.EventType)
	private, hasPrivate := nestedBool(payload.Payload, "repository", "private")
	visibility := nestedString(payload.Payload, "repository", "visibility")
	if normalized != "PUBLIC_REPOSITORY_CREATED" && (!hasPrivate || private) && visibility != "public" {
		return nil
	}
	repository := firstNonEmpty(
		nestedString(payload.Payload, "repository", "full_name"),
		nestedString(payload.Payload, "repository", "name"),
		"unknown repository",
	)
	return []Finding{{
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
	}}
}

func DedupeKey(payload JobPayload, finding Finding) string {
	encoded, _ := json.Marshal(struct {
		OrganizationID string `json:"organizationId"`
		IntegrationID  string `json:"integrationId"`
		Provider       string `json:"provider"`
		RuleID         string `json:"ruleId"`
		Target         string `json:"target"`
	}{
		OrganizationID: payload.OrganizationID,
		IntegrationID:  payload.IntegrationID,
		Provider:       payload.Provider,
		RuleID:         finding.RuleID,
		Target:         finding.Target,
	})
	sum := sha256.Sum256(encoded)
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
		if err := w.process(ctx, item); err != nil {
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
			  AND provider = 'GITHUB'
			  AND event_type = 'PUBLIC_REPOSITORY_CREATED'
			  AND (
					(status IN ('QUEUED', 'FAILED') AND (lease_expires_at IS NULL OR lease_expires_at <= NOW()))
				 OR (status = 'RUNNING' AND lease_expires_at <= NOW())
			  )
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, integration_id, provider::text, event_type, source, actor, occurred_at, payload, attempts, max_attempts
	`, w.leaseOwner, time.Now().Add(leaseDuration), limit)
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
		return w.finish(ctx, item, false, err.Error())
	}
	findings, err := w.findingsForJob(ctx, payload, item)
	if err != nil {
		return w.finish(ctx, item, false, err.Error())
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return w.finish(ctx, item, false, err.Error())
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
		return w.finish(ctx, item, false, err.Error())
	}
	eventID := "evt_" + randomID()
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO ingested_events (id, organization_id, integration_id, ingestion_job_id, provider, event_type, source, actor, severity, payload, processing_status, occurred_at, processed_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'INFO',$9,'PROCESSED',$10,NOW(),NOW())
		ON CONFLICT (ingestion_job_id) DO UPDATE SET payload = EXCLUDED.payload, processing_status = 'PROCESSED', processed_at = NOW()
		RETURNING id
	`, eventID, item.OrganizationID, item.IntegrationID, item.ID, item.Provider, item.EventType, item.Source, nullableString(item.Actor), item.Payload, item.OccurredAt).Scan(&eventID); err != nil {
		return fail(err)
	}
	for _, finding := range findings {
		if err := upsertFinding(ctx, tx, payload, finding, eventID); err != nil {
			return fail(err)
		}
		if err := enqueueFindingDelivery(ctx, tx, payload, finding); err != nil {
			return fail(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_owner = $2
	`, item.ID, w.leaseOwner); err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		txDone = true
		return w.finish(ctx, item, false, err.Error())
	}
	txDone = true
	return nil
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
		WHERE id = $1 AND organization_id = $2 AND provider = $3 AND status = 'CONNECTED'
	`, item.IntegrationID, item.OrganizationID, item.Provider).Scan(&raw); err != nil {
		return nil, err
	}
	disabledChecks := []string{}
	if err := json.Unmarshal([]byte(raw), &disabledChecks); err != nil {
		return nil, err
	}
	return disabledChecks, nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding, eventID string) error {
	dedupe := DedupeKey(payload, finding)
	evidence := map[string]any{}
	for key, value := range finding.Evidence {
		evidence[key] = value
	}
	evidence["ruleId"] = finding.RuleID
	evidence["sourceEventId"] = eventID
	evidenceJSON, _ := json.Marshal(evidence)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO security_findings (
			id, organization_id, integration_id, event_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'OPEN',$9,$10,$11,$12)
		ON CONFLICT (organization_id, dedupe_key) DO UPDATE SET
			event_id = EXCLUDED.event_id,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			status = CASE WHEN security_findings.status = 'MUTED' THEN 'MUTED' ELSE 'OPEN' END,
			risk_score = EXCLUDED.risk_score,
			remediation_steps = EXCLUDED.remediation_steps,
			evidence = EXCLUDED.evidence
	`, "fnd_"+randomID(), payload.OrganizationID, payload.IntegrationID, eventID, dedupe, finding.Title, finding.Description, finding.Severity, finding.RiskScore, finding.RemediationSteps, json.RawMessage(evidenceJSON), payload.OccurredAt)
	return err
}

func enqueueFindingDelivery(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id
		FROM siem_destinations
		WHERE organization_id = $1 AND status IN ('ACTIVE', 'ERROR') AND 'FINDINGS' = ANY(streams)
	`, payload.OrganizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var destinationID string
		if err := rows.Scan(&destinationID); err != nil {
			return err
		}
		record := map[string]any{
			"findingId":     DedupeKey(payload, finding),
			"dedupeKey":     DedupeKey(payload, finding),
			"title":         finding.Title,
			"description":   finding.Description,
			"severity":      finding.Severity,
			"riskScore":     finding.RiskScore,
			"status":        "OPEN",
			"ruleId":        finding.RuleID,
			"target":        finding.Target,
			"integrationId": payload.IntegrationID,
			"provider":      payload.Provider,
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
			VALUES ($1,$2,$3,'FINDINGS',$4,$5,NOW(),NOW())
			ON CONFLICT (organization_id, destination_id, stream, dedupe_key) DO NOTHING
		`, "sdel_"+randomID(), payload.OrganizationID, destinationID, siemdispatcher.StableDeliveryKey(deliveryPayload, destinationID, "FINDINGS"), json.RawMessage(payloadJSON))
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

func (w *Worker) finish(ctx context.Context, item job, ok bool, message string) error {
	if ok {
		_, err := w.db.ExecContext(ctx, `
			UPDATE ingestion_jobs
			SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $1 AND lease_owner = $2
		`, item.ID, w.leaseOwner)
		return err
	}
	attempts := item.Attempts + 1
	status := "FAILED"
	if attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	_, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6
	`, status, attempts, time.Now().Add(nextRetryDelay(attempts)), truncate(message, 500), item.ID, w.leaseOwner)
	return err
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
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), ".", "_"))
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
