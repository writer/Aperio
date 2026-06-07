package siemdispatcher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type siemParityFixture struct {
	DestinationID       string          `json:"destinationId"`
	Stream              string          `json:"stream"`
	Payload             Payload         `json:"payload"`
	ExpectedDeliveryKey string          `json:"expectedDeliveryKey"`
	ReopenedSourceEvent string          `json:"reopenedSourceEventId"`
	ReopenedOccurredAt  string          `json:"reopenedOccurredAt"`
	RawPayload          json.RawMessage `json:"-"`
}

type siemDedupeCasesFixture struct {
	Cases []struct {
		Name                string  `json:"name"`
		DestinationID       string  `json:"destinationId"`
		Stream              string  `json:"stream"`
		Payload             Payload `json:"payload"`
		ExpectedDeliveryKey string  `json:"expectedDeliveryKey"`
	} `json:"cases"`
}

type siemEnvelopeCasesFixture struct {
	Cases []struct {
		Name             string          `json:"name"`
		DestinationID    string          `json:"destinationId"`
		OrganizationID   string          `json:"organizationId"`
		Payload          Payload         `json:"payload"`
		ExpectedEnvelope json.RawMessage `json:"expectedEnvelope"`
	} `json:"cases"`
}

type genericWebhookFixture struct {
	Destination struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
		EndpointURL    string `json:"endpointUrl"`
		Token          string `json:"token"`
	} `json:"destination"`
	Payload         Payload `json:"payload"`
	ExpectedRequest struct {
		Method          string          `json:"method"`
		URL             string          `json:"url"`
		ContentType     string          `json:"contentType"`
		SignatureHeader string          `json:"signatureHeader"`
		Signature       string          `json:"signature"`
		Body            json.RawMessage `json:"body"`
	} `json:"expectedRequest"`
}

type captureTransport struct {
	calls    int
	method   string
	url      string
	header   http.Header
	body     []byte
	status   int
	location string
	err      error
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	c.method = req.Method
	c.url = req.URL.String()
	c.header = req.Header.Clone()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	c.body = body
	if c.err != nil {
		return nil, c.err
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	header := make(http.Header)
	if c.location != "" {
		header.Set("location", c.location)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

type staticResolver struct {
	addresses []net.IPAddr
	err       error
}

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, r.err
}

func assertJSONEqual(t *testing.T, name string, got []byte, want []byte) {
	t.Helper()
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("%s decode actual JSON: %v", name, err)
	}
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("%s decode expected JSON: %v", name, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("%s JSON = %s, want %s", name, string(got), string(want))
	}
}

func readJSONFixture[T any](t *testing.T, filename string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", filename))
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	var fixture T
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode %s: %v", filename, err)
	}
	return fixture
}

func readSiemParityFixture(t *testing.T) siemParityFixture {
	t.Helper()
	fixture := readJSONFixture[siemParityFixture](t, "siem-finding-delivery.json")
	fixture.RawPayload, _ = json.Marshal(fixture)
	return fixture
}

func TestStableDeliveryKeyIncludesFindingOccurrence(t *testing.T) {
	fixture := readSiemParityFixture(t)
	payload := fixture.Payload
	first := StableDeliveryKey(payload, fixture.DestinationID, fixture.Stream)
	reopenedPayload := payload
	reopenedPayload.OccurredAt = fixture.ReopenedOccurredAt
	reopenedPayload.Record = map[string]any{}
	for key, value := range payload.Record {
		reopenedPayload.Record[key] = value
	}
	reopenedPayload.Record["sourceEventId"] = fixture.ReopenedSourceEvent
	reopened := StableDeliveryKey(reopenedPayload, fixture.DestinationID, fixture.Stream)
	if first != fixture.ExpectedDeliveryKey {
		t.Fatalf("delivery key = %s, want shared golden %s", first, fixture.ExpectedDeliveryKey)
	}
	if first == reopened {
		t.Fatal("expected reopened finding occurrence to produce a distinct key")
	}
	if first != StableDeliveryKey(payload, fixture.DestinationID, fixture.Stream) {
		t.Fatal("expected stable delivery key to be deterministic")
	}
}

func TestStableDeliveryKeySharedCases(t *testing.T) {
	fixture := readJSONFixture[siemDedupeCasesFixture](t, "siem-dedupe-cases.json")
	seen := map[string]struct{}{}
	for _, testCase := range fixture.Cases {
		got := StableDeliveryKey(testCase.Payload, testCase.DestinationID, testCase.Stream)
		if got != testCase.ExpectedDeliveryKey {
			t.Fatalf("%s delivery key = %s, want %s", testCase.Name, got, testCase.ExpectedDeliveryKey)
		}
		if _, ok := seen[got]; ok {
			t.Fatalf("%s produced duplicate delivery key %s", testCase.Name, got)
		}
		seen[got] = struct{}{}
	}
}

func TestBuildEnvelopeUsesCanonicalSIEMShape(t *testing.T) {
	payload := Payload{
		Kind:           "event",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "evt_1"},
	}
	envelope := BuildEnvelope("dst_1", "org_1", payload)
	if envelope.SchemaVersion != "aperio.event.v1" {
		t.Fatalf("schema version = %s", envelope.SchemaVersion)
	}
	if envelope.Source != "aperio" || envelope.Producer != "aperio.sspm" {
		t.Fatalf("unexpected source/producer: %#v", envelope)
	}
	if envelope.DestinationID != "dst_1" || envelope.OrganizationID != "org_1" {
		t.Fatalf("unexpected routing fields: %#v", envelope)
	}
}

func TestBuildEnvelopeSharedCases(t *testing.T) {
	fixture := readJSONFixture[siemEnvelopeCasesFixture](t, "siem-envelope-cases.json")
	for _, testCase := range fixture.Cases {
		envelope := BuildEnvelope(testCase.DestinationID, testCase.OrganizationID, testCase.Payload)
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("%s marshal envelope: %v", testCase.Name, err)
		}
		assertJSONEqual(t, testCase.Name, encoded, testCase.ExpectedEnvelope)
	}
}

func TestSendGenericWebhookCapturesReferenceRequestShape(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[genericWebhookFixture](t, "siem-generic-webhook-delivery.json")
	destination := destination{
		ID:             fixture.Destination.ID,
		OrganizationID: fixture.Destination.OrganizationID,
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: fixture.Destination.EndpointURL, Valid: true},
	}
	destination.EncryptedToken = sql.NullString{
		String: encryptForDispatcherTest(t, fixture.Destination.Token, destinationTokenAAD(destination)),
		Valid:  true,
	}
	transport := &captureTransport{}
	safetyChecked := false
	dispatcher := &Dispatcher{
		httpClient: &http.Client{Transport: transport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			safetyChecked = true
			if endpoint != fixture.ExpectedRequest.URL {
				t.Fatalf("endpoint safety checked %q, want %q", endpoint, fixture.ExpectedRequest.URL)
			}
			return nil
		},
	}

	if err := dispatcher.sendGenericWebhook(context.Background(), destination, fixture.Payload); err != nil {
		t.Fatalf("send generic webhook: %v", err)
	}
	if !safetyChecked {
		t.Fatal("expected send-time endpoint safety check")
	}
	if transport.calls != 1 {
		t.Fatalf("expected one request, got %d", transport.calls)
	}
	if transport.method != fixture.ExpectedRequest.Method || transport.url != fixture.ExpectedRequest.URL {
		t.Fatalf("request = %s %s", transport.method, transport.url)
	}
	if transport.header.Get("content-type") != fixture.ExpectedRequest.ContentType {
		t.Fatalf("content-type = %q", transport.header.Get("content-type"))
	}
	if got := transport.header.Get(fixture.ExpectedRequest.SignatureHeader); got != fixture.ExpectedRequest.Signature {
		t.Fatalf("signature = %s, want %s", got, fixture.ExpectedRequest.Signature)
	}
	assertJSONEqual(t, "generic webhook body", transport.body, fixture.ExpectedRequest.Body)
	if strings.Contains(string(transport.body), fixture.Destination.Token) {
		t.Fatal("webhook request body must not contain the signing secret")
	}
}

func TestDecryptStringFailsClosedForCredentialEnvelopeErrors(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	aad := "org_1:siem:dst_1:token"
	plaintext := "fixture-siem-token-not-secret"
	validEnvelope := "eyJ2ZXJzaW9uIjoxLCJhbGdvcml0aG0iOiJhZXMtMjU2LWdjbSIsIml2IjoiTVRJek5EVTJOemc1TURFeSIsInRhZyI6Im1sUjJUS1QyMmdsMHBOOTRNa0NYX3ciLCJjaXBoZXJ0ZXh0IjoiN1Qta25Jc0lRakVsOW1XQWRNSjNfUDJQaDE5X3RVellFaDgifQ"

	t.Run("missing key", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", "")
		_, err := decryptString(validEnvelope, "org_demo:GITHUB:writer:access_token")
		if err == nil || !strings.Contains(err.Error(), "APERIO_ENCRYPTION_KEY is required") {
			t.Fatalf("expected missing key failure, got %v", err)
		}
		if strings.Contains(err.Error(), "demo-provider-token-GITHUB") {
			t.Fatal("missing-key error leaked plaintext credential")
		}
	})

	for _, testCase := range []struct {
		name      string
		encrypted func(t *testing.T) string
		aad       string
	}{
		{
			name:      "malformed envelope",
			encrypted: func(*testing.T) string { return "not-a-valid-envelope" },
			aad:       aad,
		},
		{
			name: "wrong aad",
			encrypted: func(t *testing.T) string {
				return encryptForDispatcherTest(t, plaintext, aad)
			},
			aad: aad + ":wrong",
		},
		{
			name: "tampered tag",
			encrypted: func(t *testing.T) string {
				return tamperEncryptedTagForDispatcherTest(t, encryptForDispatcherTest(t, plaintext, aad))
			},
			aad: aad,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
			_, err := decryptString(testCase.encrypted(t), testCase.aad)
			if err == nil {
				t.Fatal("expected decrypt failure")
			}
			if strings.Contains(err.Error(), plaintext) {
				t.Fatalf("decrypt error leaked plaintext credential: %v", err)
			}
		})
	}
}

func TestSendGenericWebhookEndpointSafetyBlocksHTTP(t *testing.T) {
	transport := &captureTransport{}
	dispatcher := &Dispatcher{httpClient: &http.Client{Transport: transport}}
	err := dispatcher.sendGenericWebhook(context.Background(), destination{
		ID:             "dst_webhook_unsafe",
		OrganizationID: "org_1",
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: "https://127.0.0.1:9000/aperio", Valid: true},
	}, Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "fnd_1"},
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback endpoint safety error, got %v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("unsafe endpoint should be blocked before HTTP, got %d calls", transport.calls)
	}
}

func TestSendGenericWebhookDoesNotFollowRedirects(t *testing.T) {
	transport := &captureTransport{
		status:   http.StatusFound,
		location: "https://169.254.169.254/latest/meta-data",
	}
	dispatcher := &Dispatcher{
		httpClient:          &http.Client{Transport: transport},
		endpointSafetyCheck: func(context.Context, string) error { return nil },
	}
	err := dispatcher.sendGenericWebhook(context.Background(), destination{
		ID:             "dst_webhook_redirect",
		OrganizationID: "org_1",
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: "https://webhook.receiver.example/aperio", Valid: true},
	}, Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "fnd_1"},
	})
	if err == nil || !strings.Contains(err.Error(), "302 Found") {
		t.Fatalf("expected redirect response to fail without following, got %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("redirect should not be followed, got %d calls", transport.calls)
	}
}

func TestEndpointSafetyRejectsDNSRebindingToPrivateAddress(t *testing.T) {
	err := assertSafeEndpointURLWithResolver(
		context.Background(),
		"https://webhook.receiver.example/aperio",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	)
	if err == nil || !strings.Contains(err.Error(), "private addresses") {
		t.Fatalf("expected DNS private-address rejection, got %v", err)
	}
	if err := assertSafeEndpointURLWithResolver(
		context.Background(),
		"https://8.8.8.8/aperio",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	); err != nil {
		t.Fatalf("public literal IP should not require DNS resolver, got %v", err)
	}
}

func TestSafeDialAddressUsesValidatedResolvedIP(t *testing.T) {
	if _, err := safeDialAddress(
		context.Background(),
		"webhook.receiver.example:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	); err == nil || !strings.Contains(err.Error(), "private addresses") {
		t.Fatalf("expected private resolved address rejection, got %v", err)
	}

	target, err := safeDialAddress(
		context.Background(),
		"webhook.receiver.example:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}},
	)
	if err != nil {
		t.Fatalf("public resolved address rejected: %v", err)
	}
	if target != "8.8.8.8:443" {
		t.Fatalf("dial target = %q, want resolved IP target", target)
	}

	if _, err := safeDialAddress(
		context.Background(),
		"127.0.0.1:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}},
	); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected private literal rejection, got %v", err)
	}
}

func TestNormalizeFilePathConfinesRawDatabasePathsToExportRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", root)
	relativePath, err := normalizeFilePath("tenant-a/findings.jsonl")
	if err != nil {
		t.Fatalf("relative path: %v", err)
	}
	if relativePath != filepath.Join(root, "tenant-a", "findings.jsonl") {
		t.Fatalf("relative path normalized to %s", relativePath)
	}
	insideAbsolute := filepath.Join(root, "absolute", "findings.jsonl")
	if got, err := normalizeFilePath(insideAbsolute); err != nil || got != insideAbsolute {
		t.Fatalf("inside absolute path = %s err=%v", got, err)
	}
	for _, unsafe := range []string{
		"../escape.jsonl",
		filepath.Join(root+"-sibling", "findings.jsonl"),
		root,
	} {
		if got, err := normalizeFilePath(unsafe); err == nil {
			t.Fatalf("expected %q to be rejected, got %s", unsafe, got)
		}
	}
}

func TestDestinationLoadFailureOnlyPermanentForMissingRows(t *testing.T) {
	permanent, message := destinationLoadFailure(sql.ErrNoRows)
	if !permanent || message != "destination not active" {
		t.Fatalf("expected missing destination to be permanent, got permanent=%v message=%q", permanent, message)
	}

	permanent, message = destinationLoadFailure(errors.New("statement timeout"))
	if permanent {
		t.Fatalf("expected transient load error to retry, got permanent with message %q", message)
	}
	if message != "statement timeout" {
		t.Fatalf("unexpected transient message %q", message)
	}
}

func encryptForDispatcherTest(t *testing.T, plaintext string, aad string) string {
	t.Helper()
	key, err := resolveEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	tagStart := len(sealed) - gcm.Overhead()
	envelope := encryptedEnvelope{
		Version:    1,
		Algorithm:  encryptionAlgorithm,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Tag:        base64.RawURLEncoding.EncodeToString(sealed[tagStart:]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed[:tagStart]),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func tamperEncryptedTagForDispatcherTest(t *testing.T, encrypted string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Tag = base64.RawURLEncoding.EncodeToString(make([]byte, encryptionNonceBytes+4))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func TestProcessReturnsErrorForRecordedFailure(t *testing.T) {
	state := &dispatcherDriverState{}
	driverName := fmt.Sprintf("siem_failure_%d", time.Now().UnixNano())
	sql.Register(driverName, &dispatcherDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	dispatcher := &Dispatcher{db: db, leaseOwner: "test-owner"}
	err = dispatcher.process(context.Background(), delivery{
		ID:             "del_1",
		OrganizationID: "org_1",
		Payload:        json.RawMessage(`{"kind":"unknown","organizationId":"org_1","occurredAt":"2026-06-06T00:00:00Z","record":{}}`),
		Attempts:       0,
		MaxAttempts:    3,
	})
	if err == nil {
		t.Fatal("expected process to return the delivery failure after recording it")
	}

	status, attempts, message := state.failureUpdate()
	if status != "DEAD_LETTER" || attempts != "1" {
		t.Fatalf("expected recorded dead-letter attempt, got status=%s attempts=%s", status, attempts)
	}
	if !strings.Contains(message, "invalid delivery kind") {
		t.Fatalf("expected recorded parse error, got %q", message)
	}
}

type dispatcherDriverState struct {
	mu    sync.Mutex
	execs [][]driver.NamedValue
}

func (s *dispatcherDriverState) failureUpdate() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.execs) == 0 {
		return "", "", ""
	}
	args := s.execs[len(s.execs)-1]
	return fmt.Sprint(args[0].Value), fmt.Sprint(args[1].Value), fmt.Sprint(args[3].Value)
}

type dispatcherDriver struct {
	state *dispatcherDriverState
}

func (d *dispatcherDriver) Open(string) (driver.Conn, error) {
	return &dispatcherConn{state: d.state}, nil
}

type dispatcherConn struct {
	state *dispatcherDriverState
}

func (c *dispatcherConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}

func (c *dispatcherConn) Close() error {
	return nil
}

func (c *dispatcherConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions not supported")
}

func (c *dispatcherConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "UPDATE siem_deliveries") {
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	c.state.mu.Lock()
	c.state.execs = append(c.state.execs, args)
	c.state.mu.Unlock()
	return driver.RowsAffected(1), nil
}
