package siemdispatcher

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
	"path/filepath"
	"strings"
	"time"
)

const leaseDuration = 5 * time.Minute

type Payload struct {
	Kind           string         `json:"kind"`
	OrganizationID string         `json:"organizationId"`
	OccurredAt     string         `json:"occurredAt"`
	Record         map[string]any `json:"record"`
}

type Envelope struct {
	SchemaVersion  string         `json:"schema_version"`
	Source         string         `json:"source"`
	Producer       string         `json:"producer"`
	DestinationID  string         `json:"destination_id"`
	OrganizationID string         `json:"organization_id"`
	Kind           string         `json:"kind"`
	OccurredAt     string         `json:"occurred_at"`
	Record         map[string]any `json:"record"`
}

type Result struct {
	Processed int
	Delivered int
	Failed    int
}

type Dispatcher struct {
	db         *sql.DB
	leaseOwner string
}

type delivery struct {
	ID             string
	OrganizationID string
	DestinationID  sql.NullString
	Stream         string
	Payload        json.RawMessage
	Attempts       int
	MaxAttempts    int
}

type destination struct {
	ID             string
	OrganizationID string
	Kind           string
	Name           string
	EndpointURL    sql.NullString
	FilePath       sql.NullString
	Index          sql.NullString
}

func New(db *sql.DB) *Dispatcher {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	return &Dispatcher{
		db:         db,
		leaseOwner: fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), randomID()),
	}
}

func StableDeliveryKey(payload Payload, destinationID string, stream string) string {
	record := payload.Record
	stableRecordID := firstString(record["findingId"], record["id"], record["dedupeKey"], record["sourceEventId"])
	if stableRecordID == "" {
		encoded, _ := json.Marshal(record)
		stableRecordID = string(encoded)
	}
	key := struct {
		OrganizationID    string `json:"organizationId"`
		DestinationID     string `json:"destinationId"`
		Stream            string `json:"stream"`
		Kind              string `json:"kind"`
		StableRecordID    string `json:"stableRecordId"`
		FindingOccurrence string `json:"findingOccurrence,omitempty"`
		FindingStatus     string `json:"findingStatus,omitempty"`
	}{
		OrganizationID: payload.OrganizationID,
		DestinationID:  destinationID,
		Stream:         stream,
		Kind:           payload.Kind,
		StableRecordID: stableRecordID,
	}
	if payload.Kind == "finding" {
		key.FindingOccurrence = firstString(record["sourceEventId"], record["detectedAt"], payload.OccurredAt)
		key.FindingStatus = firstString(record["status"])
	}
	encoded, _ := json.Marshal(key)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (d *Dispatcher) Drain(ctx context.Context, limit int) (Result, error) {
	if d.db == nil {
		return Result{}, errors.New("database is required")
	}
	limit = boundedLimit(limit)
	if err := d.retireExhausted(ctx); err != nil {
		return Result{}, err
	}
	deliveries, err := d.claim(ctx, limit)
	if err != nil {
		return Result{}, err
	}
	result := Result{Processed: len(deliveries)}
	for _, delivery := range deliveries {
		if err := d.process(ctx, delivery); err != nil {
			result.Failed++
		} else {
			result.Delivered++
		}
	}
	return result, nil
}

func (d *Dispatcher) retireExhausted(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'DEAD_LETTER', lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW()
		WHERE attempts >= max_attempts
		  AND status IN ('PENDING', 'FAILED', 'PROCESSING')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
	`)
	return err
}

func (d *Dispatcher) claim(ctx context.Context, limit int) ([]delivery, error) {
	rows, err := d.db.QueryContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'PROCESSING', lease_owner = $1, lease_expires_at = $2, updated_at = NOW()
		WHERE id IN (
			SELECT sd.id
			FROM siem_deliveries sd
			JOIN siem_destinations dst
			  ON dst.id = sd.destination_id
			 AND dst.organization_id = sd.organization_id
			WHERE sd.attempts < sd.max_attempts
			  AND sd.next_attempt_at <= NOW()
			  AND dst.status IN ('ACTIVE', 'ERROR')
			  AND dst.kind = 'JSON_FILE'
			  AND (
					(sd.status IN ('PENDING', 'FAILED') AND (sd.lease_expires_at IS NULL OR sd.lease_expires_at <= NOW()))
				 OR (sd.status = 'PROCESSING' AND sd.lease_expires_at <= NOW())
			  )
			ORDER BY sd.created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, destination_id, stream::text, payload, attempts, max_attempts
	`, d.leaseOwner, time.Now().Add(leaseDuration), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := []delivery{}
	for rows.Next() {
		var item delivery
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.DestinationID, &item.Stream, &item.Payload, &item.Attempts, &item.MaxAttempts); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, item)
	}
	return deliveries, rows.Err()
}

func (d *Dispatcher) process(ctx context.Context, item delivery) error {
	payload, err := parsePayload(item.Payload)
	if err != nil {
		return d.finish(ctx, item, false, true, err.Error())
	}
	if !item.DestinationID.Valid {
		return d.finish(ctx, item, false, true, "destination not configured")
	}
	dest, err := d.loadDestination(ctx, item.OrganizationID, item.DestinationID.String)
	if err != nil {
		permanent, message := destinationLoadFailure(err)
		return d.finish(ctx, item, false, permanent, message)
	}
	switch dest.Kind {
	case "JSON_FILE":
		err = writeJSONFile(dest, payload)
	default:
		err = fmt.Errorf("unsupported Go SIEM destination kind %s", dest.Kind)
	}
	if err != nil {
		return d.finish(ctx, item, false, false, err.Error())
	}
	if err := d.finish(ctx, item, true, false, ""); err != nil {
		return err
	}
	_, _ = d.db.ExecContext(ctx, `
		UPDATE siem_destinations
		SET last_delivery_at = NOW(), deliveries_ok = deliveries_ok + 1, last_error = NULL, status = 'ACTIVE', updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, dest.ID, dest.OrganizationID)
	return nil
}

func (d *Dispatcher) loadDestination(ctx context.Context, organizationID string, id string) (destination, error) {
	var dest destination
	err := d.db.QueryRowContext(ctx, `
		SELECT id, organization_id, kind::text, name, endpoint_url, file_path, index
		FROM siem_destinations
		WHERE id = $1 AND organization_id = $2 AND status IN ('ACTIVE', 'ERROR')
	`, id, organizationID).Scan(&dest.ID, &dest.OrganizationID, &dest.Kind, &dest.Name, &dest.EndpointURL, &dest.FilePath, &dest.Index)
	return dest, err
}

func destinationLoadFailure(err error) (bool, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return true, "destination not active"
	}
	return false, err.Error()
}

func (d *Dispatcher) finish(ctx context.Context, item delivery, ok bool, permanent bool, message string) error {
	attempts := item.Attempts + 1
	if ok {
		_, err := d.db.ExecContext(ctx, `
			UPDATE siem_deliveries
			SET status = 'DELIVERED', attempts = $1, delivered_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $2 AND lease_owner = $3
		`, attempts, item.ID, d.leaseOwner)
		return err
	}
	status := "FAILED"
	if permanent || attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	nextAttemptAt := time.Now().Add(nextRetryDelay(attempts))
	_, err := d.db.ExecContext(ctx, `
		UPDATE siem_deliveries
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6
	`, status, attempts, nextAttemptAt, truncate(message, 500), item.ID, d.leaseOwner)
	if item.DestinationID.Valid {
		_, _ = d.db.ExecContext(ctx, `
			UPDATE siem_destinations
			SET deliveries_fail = deliveries_fail + 1, last_error = $1, status = 'ERROR', updated_at = NOW()
			WHERE id = $2 AND organization_id = $3
		`, truncate(message, 500), item.DestinationID.String, item.OrganizationID)
	}
	return err
}

func parsePayload(raw json.RawMessage) (Payload, error) {
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, err
	}
	if payload.Kind != "finding" && payload.Kind != "event" && payload.Kind != "audit_log" {
		return payload, errors.New("invalid delivery kind")
	}
	if strings.TrimSpace(payload.OrganizationID) == "" || strings.TrimSpace(payload.OccurredAt) == "" || payload.Record == nil {
		return payload, errors.New("invalid delivery payload")
	}
	return payload, nil
}

func BuildEnvelope(destID string, orgID string, payload Payload) Envelope {
	return Envelope{
		SchemaVersion:  schemaVersion(payload.Kind),
		Source:         "aperio",
		Producer:       "aperio.sspm",
		DestinationID:  destID,
		OrganizationID: orgID,
		Kind:           payload.Kind,
		OccurredAt:     payload.OccurredAt,
		Record:         payload.Record,
	}
}

func writeJSONFile(dest destination, payload Payload) error {
	if !dest.FilePath.Valid || strings.TrimSpace(dest.FilePath.String) == "" {
		return errors.New("file_path is not configured")
	}
	path, err := normalizeFilePath(dest.FilePath.String)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(encoded, '\n'))
	return err
}

func normalizeFilePath(raw string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(raw))
	if cleaned == "." || strings.HasPrefix(cleaned, "~") || strings.Contains(cleaned, "..") {
		return "", errors.New("invalid SIEM export path")
	}
	if filepath.IsAbs(cleaned) {
		return cleaned, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, "var", "siem-exports", cleaned), nil
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

func schemaVersion(kind string) string {
	switch kind {
	case "finding":
		return "aperio.finding.v1"
	case "event":
		return "aperio.event.v1"
	default:
		return "aperio.audit_log.v1"
	}
}

func firstString(values ...any) string {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case float64:
			return fmt.Sprintf("%v", typed)
		case bool:
			return fmt.Sprintf("%t", typed)
		}
	}
	return ""
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
