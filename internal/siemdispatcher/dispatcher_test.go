package siemdispatcher

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func readSiemParityFixture(t *testing.T) siemParityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "siem-finding-delivery.json"))
	if err != nil {
		t.Fatalf("read SIEM parity fixture: %v", err)
	}
	var fixture siemParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode SIEM parity fixture: %v", err)
	}
	fixture.RawPayload = raw
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
