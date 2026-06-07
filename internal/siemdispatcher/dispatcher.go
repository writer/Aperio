package siemdispatcher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	leaseDuration        = 5 * time.Minute
	networkTimeout       = 4 * time.Second
	encryptionAlgorithm  = "aes-256-gcm"
	encryptionKeyBytes   = 32
	encryptionNonceBytes = 12
)

var errDeliveryLeaseLost = errors.New("siem delivery lease lost")

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
	db                  *sql.DB
	leaseOwner          string
	organizationID      string
	httpClient          *http.Client
	endpointSafetyCheck func(context.Context, string) error
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
	EncryptedToken sql.NullString
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	IV         string `json:"iv"`
	Tag        string `json:"tag"`
	Ciphertext string `json:"ciphertext"`
}

type endpointResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
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

// SetOrganizationForTesting scopes drain queries to one organization in DB-backed tests.
func (d *Dispatcher) SetOrganizationForTesting(organizationID string) {
	d.organizationID = organizationID
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
		  AND ($1 = '' OR organization_id = $1)
		  AND status IN ('PENDING', 'FAILED', 'PROCESSING')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
		  AND (payload->>'organizationId' IS NULL OR payload->>'organizationId' = organization_id)
		  AND (
		    destination_id IS NULL OR EXISTS (
			SELECT 1
			FROM siem_destinations dst
			WHERE dst.id = siem_deliveries.destination_id
			  AND dst.organization_id = siem_deliveries.organization_id
			  AND dst.kind IN ('JSON_FILE', 'GENERIC_WEBHOOK')
			  AND siem_deliveries.stream = ANY(dst.streams)
		    )
		  )
	`, d.organizationID)
	return err
}

func (d *Dispatcher) claim(ctx context.Context, limit int) ([]delivery, error) {
	rows, err := d.db.QueryContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'PROCESSING', lease_owner = $1, lease_expires_at = $2, updated_at = NOW()
		WHERE id IN (
			SELECT sd.id
			FROM siem_deliveries sd
			WHERE sd.attempts < sd.max_attempts
			  AND ($4 = '' OR sd.organization_id = $4)
			  AND sd.next_attempt_at <= NOW()
			  AND (sd.payload->>'organizationId' IS NULL OR sd.payload->>'organizationId' = sd.organization_id)
			  AND (
					sd.destination_id IS NULL OR EXISTS (
						SELECT 1
						FROM siem_destinations dst
						WHERE dst.id = sd.destination_id
						AND dst.organization_id = sd.organization_id
						AND dst.status IN ('ACTIVE', 'ERROR')
						AND dst.kind IN ('JSON_FILE', 'GENERIC_WEBHOOK')
						AND sd.stream = ANY(dst.streams)
					)
			  )
			  AND (
					(sd.status IN ('PENDING', 'FAILED') AND (sd.lease_expires_at IS NULL OR sd.lease_expires_at <= NOW()))
				 OR (sd.status = 'PROCESSING' AND sd.lease_expires_at <= NOW())
			  )
			ORDER BY sd.created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, destination_id, stream::text, payload, attempts, max_attempts
	`, d.leaseOwner, time.Now().UTC().Add(leaseDuration), limit, d.organizationID)
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
		return d.failDelivery(ctx, item, true, err.Error())
	}
	if payload.OrganizationID != item.OrganizationID {
		return d.failDelivery(ctx, item, true, "delivery payload organization mismatch")
	}
	return d.processPayload(ctx, item, payload)
}

func (d *Dispatcher) processPayload(ctx context.Context, item delivery, payload Payload) error {
	if !item.DestinationID.Valid {
		return d.failDelivery(ctx, item, true, "destination not configured")
	}
	dest, err := d.loadDestination(ctx, item.OrganizationID, item.DestinationID.String, item.Stream)
	if err != nil {
		permanent, message := destinationLoadFailure(err)
		return d.failDelivery(ctx, item, permanent, message)
	}
	switch dest.Kind {
	case "JSON_FILE":
		err = writeJSONFile(dest, payload)
	case "GENERIC_WEBHOOK":
		err = d.sendGenericWebhook(ctx, dest, payload)
	default:
		err = fmt.Errorf("unsupported Go SIEM destination kind %s", dest.Kind)
	}
	if err != nil {
		return d.fail(ctx, item, false, err.Error())
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

func (d *Dispatcher) fail(ctx context.Context, item delivery, permanent bool, message string) error {
	return d.failWithHealth(ctx, item, permanent, message, true)
}

func (d *Dispatcher) failDelivery(ctx context.Context, item delivery, permanent bool, message string) error {
	return d.failWithHealth(ctx, item, permanent, message, false)
}

func (d *Dispatcher) failWithHealth(ctx context.Context, item delivery, permanent bool, message string, updateDestinationHealth bool) error {
	if err := d.finish(ctx, item, false, permanent, message, updateDestinationHealth); err != nil {
		return err
	}
	return errors.New(message)
}

func (d *Dispatcher) loadDestination(ctx context.Context, organizationID string, id string, stream string) (destination, error) {
	var dest destination
	err := d.db.QueryRowContext(ctx, `
		SELECT id, organization_id, kind::text, name, endpoint_url, file_path, index, encrypted_token
		FROM siem_destinations
		WHERE id = $1 AND organization_id = $2 AND status IN ('ACTIVE', 'ERROR') AND $3::"SiemStreamType" = ANY(streams)
	`, id, organizationID, stream).Scan(&dest.ID, &dest.OrganizationID, &dest.Kind, &dest.Name, &dest.EndpointURL, &dest.FilePath, &dest.Index, &dest.EncryptedToken)
	return dest, err
}

func destinationLoadFailure(err error) (bool, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return true, "destination not active"
	}
	return false, err.Error()
}

func (d *Dispatcher) finish(ctx context.Context, item delivery, ok bool, permanent bool, message string, updateDestinationHealth ...bool) error {
	attempts := item.Attempts + 1
	if ok {
		res, err := d.db.ExecContext(ctx, `
			UPDATE siem_deliveries
			SET status = 'DELIVERED', attempts = $1, delivered_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $2 AND lease_owner = $3
		`, attempts, item.ID, d.leaseOwner)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil && rows != 1 {
			return errDeliveryLeaseLost
		}
		return nil
	}
	status := "FAILED"
	if permanent || attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	nextAttemptAt := time.Now().UTC().Add(nextRetryDelay(attempts))
	res, err := d.db.ExecContext(ctx, `
		UPDATE siem_deliveries
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6
	`, status, attempts, nextAttemptAt, truncate(message, 500), item.ID, d.leaseOwner)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		return errDeliveryLeaseLost
	}
	shouldUpdateDestinationHealth := true
	if len(updateDestinationHealth) > 0 {
		shouldUpdateDestinationHealth = updateDestinationHealth[0]
	}
	if shouldUpdateDestinationHealth && item.DestinationID.Valid {
		_, _ = d.db.ExecContext(ctx, `
			UPDATE siem_destinations
			SET deliveries_fail = deliveries_fail + 1, last_error = $1, status = 'ERROR', updated_at = NOW()
			WHERE id = $2 AND organization_id = $3
		`, truncate(message, 500), item.DestinationID.String, item.OrganizationID)
	}
	return nil
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

func (d *Dispatcher) sendGenericWebhook(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return errors.New("endpoint not configured")
	}
	bodyBytes, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	headers := map[string]string{}
	if dest.EncryptedToken.Valid && strings.TrimSpace(dest.EncryptedToken.String) != "" {
		token, err := decryptString(dest.EncryptedToken.String, destinationTokenAAD(dest))
		if err != nil {
			return errors.New("SIEM token decrypt failed")
		}
		signature := hmac.New(sha256.New, []byte(token))
		_, _ = signature.Write(bodyBytes)
		headers["x-aperio-signature"] = hex.EncodeToString(signature.Sum(nil))
	}
	return d.postJSON(ctx, dest.EndpointURL.String, headers, bodyBytes)
}

func (d *Dispatcher) postJSON(ctx context.Context, endpoint string, headers map[string]string, body []byte) error {
	if err := d.checkEndpoint(ctx, endpoint); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := d.webhookHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		statusText := strings.TrimSpace(http.StatusText(res.StatusCode))
		if statusText == "" {
			statusText = "HTTP error"
		}
		return fmt.Errorf("%d %s", res.StatusCode, statusText)
	}
	return nil
}

func (d *Dispatcher) webhookHTTPClient() *http.Client {
	if d.httpClient != nil {
		client := *d.httpClient
		client.CheckRedirect = blockWebhookRedirect
		return &client
	}
	return &http.Client{
		Timeout:       networkTimeout,
		Transport:     safeWebhookTransport(),
		CheckRedirect: blockWebhookRedirect,
	}
}

func blockWebhookRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func safeWebhookTransport() http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	dialer := &net.Dialer{Timeout: networkTimeout, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		target, err := safeDialAddress(ctx, address, net.DefaultResolver)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, target)
	}
	return base
}

func safeDialAddress(ctx context.Context, address string, resolver endpointResolver) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("endpoint dial target is invalid")
	}
	host = normalizeHostname(host)
	if host == "" {
		return "", errors.New("endpoint URL hostname is required")
	}
	if isBlockedHostname(host) {
		return "", errors.New("endpoint URL must not target loopback, local, or private hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return "", errors.New("endpoint URL must not target loopback, local, or private hosts")
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	lookupCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		lookupCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
	}
	defer cancel()
	addresses, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("endpoint URL hostname could not be resolved")
	}
	for _, address := range addresses {
		if isPrivateIP(address.IP) {
			return "", errors.New("endpoint URL must not resolve to loopback or private addresses")
		}
	}
	return net.JoinHostPort(addresses[0].IP.String(), port), nil
}

func (d *Dispatcher) checkEndpoint(ctx context.Context, endpoint string) error {
	if d.endpointSafetyCheck != nil {
		return d.endpointSafetyCheck(ctx, endpoint)
	}
	return assertSafeEndpointURL(ctx, endpoint)
}

func normalizeFilePath(raw string) (string, error) {
	root := strings.TrimSpace(os.Getenv("APERIO_SIEM_EXPORT_DIR"))
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		root = filepath.Join(cwd, "var", "siem-exports")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid SIEM export path")
	}
	candidate := trimmed
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid SIEM export path: file path must stay within %s", root)
	}
	return candidate, nil
}

func assertSafeEndpointURL(ctx context.Context, raw string) error {
	return assertSafeEndpointURLWithResolver(ctx, raw, net.DefaultResolver)
}

func assertSafeEndpointURLWithResolver(ctx context.Context, raw string, resolver endpointResolver) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("endpoint URL must be a valid absolute URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("endpoint URL must use HTTPS")
	}
	host := normalizeHostname(parsed.Hostname())
	if host == "" {
		return errors.New("endpoint URL hostname is required")
	}
	if isBlockedHostname(host) {
		return errors.New("endpoint URL must not target loopback, local, or private hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return errors.New("endpoint URL must not target loopback, local, or private hosts")
		}
		return nil
	}
	lookupCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		lookupCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
	}
	defer cancel()
	addresses, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("endpoint URL hostname could not be resolved")
	}
	for _, address := range addresses {
		if isPrivateIP(address.IP) {
			return errors.New("endpoint URL must not resolve to loopback or private addresses")
		}
	}
	return nil
}

func normalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func isBlockedHostname(host string) bool {
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return true
	}
	for _, suffix := range []string{".internal", ".local", ".localhost", ".localdomain", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		first, second, third := int(v4[0]), int(v4[1]), int(v4[2])
		return first == 0 ||
			first == 10 ||
			first == 127 ||
			(first == 100 && second >= 64 && second <= 127) ||
			(first == 169 && second == 254) ||
			(first == 172 && second >= 16 && second <= 31) ||
			(first == 192 && second == 0 && third == 0) ||
			(first == 192 && second == 0 && third == 2) ||
			(first == 192 && second == 168) ||
			(first == 198 && (second == 18 || second == 19)) ||
			(first == 198 && second == 51 && third == 100) ||
			(first == 203 && second == 0 && third == 113) ||
			first >= 224
	}
	lower := strings.ToLower(ip.String())
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		strings.HasPrefix(lower, "2001:db8")
}

func destinationTokenAAD(dest destination) string {
	return dest.OrganizationID + ":siem:" + dest.ID + ":token"
}

func decryptString(encrypted string, additionalAuthenticatedData string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", err
	}
	if envelope.Version != 1 || envelope.Algorithm != encryptionAlgorithm {
		return "", errors.New("unsupported encrypted value")
	}
	iv, err := base64.RawURLEncoding.DecodeString(envelope.IV)
	if err != nil {
		return "", err
	}
	tag, err := base64.RawURLEncoding.DecodeString(envelope.Tag)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", err
	}
	key, err := resolveEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(iv) != gcm.NonceSize() {
		return "", errors.New("invalid encryption nonce length")
	}
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(additionalAuthenticatedData))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func resolveEncryptionKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("APERIO_ENCRYPTION_KEY"))
	if raw == "" {
		return nil, errors.New("APERIO_ENCRYPTION_KEY is required")
	}
	switch {
	case strings.HasPrefix(raw, "base64:"):
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "base64:"))
		if err != nil {
			return nil, err
		}
		if len(key) != encryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	case strings.HasPrefix(raw, "base64url:"):
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "base64url:"))
		if err != nil {
			return nil, err
		}
		if len(key) != encryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	case strings.HasPrefix(raw, "hex:"):
		key, err := hex.DecodeString(strings.TrimPrefix(raw, "hex:"))
		if err != nil {
			return nil, err
		}
		if len(key) != encryptionKeyBytes {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
		}
		return key, nil
	default:
		if os.Getenv("NODE_ENV") == "production" {
			return nil, errors.New("APERIO_ENCRYPTION_KEY must use base64:, base64url:, or hex: encoding in production")
		}
		return scrypt.Key([]byte(raw), []byte("aperio-token-vault"), 16384, 8, 1, encryptionKeyBytes)
	}
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
