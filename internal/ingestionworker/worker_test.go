package ingestionworker

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEvaluateGitHubPublicRepository(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Payload: map[string]any{
			"repository": map[string]any{
				"full_name":  "writer/aperio",
				"visibility": "public",
			},
		},
	}
	findings := Evaluate(payload, nil)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].RuleID != "github.public_repository_created" {
		t.Fatalf("rule id = %s", findings[0].RuleID)
	}
	if findings[0].Target != "writer/aperio" {
		t.Fatalf("target = %s", findings[0].Target)
	}
	if findings[0].Severity != "CRITICAL" || findings[0].RiskScore != 95 {
		t.Fatalf("unexpected severity/risk: %#v", findings[0])
	}
}

func TestDedupeKeyIsStableAcrossObservations(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
	}
	finding := Finding{RuleID: "github.public_repository_created", Target: "writer/aperio"}
	first := DedupeKey(payload, finding)
	second := DedupeKey(payload, finding)
	if first == "" || first != second {
		t.Fatalf("dedupe key not stable: %q %q", first, second)
	}
	if first != "19ee6798462d3e0e56d02df0795cfeff7114cf4f88f6f735abeff8b625b472f7" {
		t.Fatalf("dedupe key = %s, want TS-compatible hash", first)
	}
	payload.EventType = "OTHER_EVENT"
	if DedupeKey(payload, finding) != first {
		t.Fatal("dedupe key should exclude event type so repeated observations update the same finding")
	}
	payload.Provider = "SLACK"
	if DedupeKey(payload, finding) != first {
		t.Fatal("dedupe key should exclude provider to match the TypeScript worker")
	}
}

func TestProcessMarksJobFailureWhenInsertFails(t *testing.T) {
	state := &failureDriverState{}
	driverName := fmt.Sprintf("ingestion_failure_%d", time.Now().UnixNano())
	sql.Register(driverName, &failureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	worker := &Worker{db: db, leaseOwner: "test-owner"}
	payload, _ := json.Marshal(map[string]any{"repository": map[string]any{"full_name": "writer/aperio", "visibility": "public"}})
	err = worker.process(context.Background(), job{
		ID:             "job_1",
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "test",
		OccurredAt:     time.Now(),
		Payload:        payload,
		Attempts:       1,
		MaxAttempts:    3,
	})
	if err != nil {
		t.Fatalf("process should return the recorded failure update result, got %v", err)
	}

	status, attempts, message := state.failureUpdate()
	if status != "FAILED" || attempts != "2" {
		t.Fatalf("expected FAILED attempt 2, got status=%s attempts=%s", status, attempts)
	}
	if !strings.Contains(message, "ingested event insert failed") {
		t.Fatalf("expected stored error message, got %q", message)
	}
	if !state.rolledBack {
		t.Fatal("expected failed transaction to be rolled back before marking job failure")
	}
}

func TestFindingsForJobHonorsDisabledChecks(t *testing.T) {
	state := &failureDriverState{disabledChecksJSON: `["github.public_repository_created"]`}
	driverName := fmt.Sprintf("ingestion_disabled_%d", time.Now().UnixNano())
	sql.Register(driverName, &failureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	worker := &Worker{db: db}
	findings, err := worker.findingsForJob(context.Background(), JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Payload: map[string]any{
			"repository": map[string]any{
				"full_name":  "writer/aperio",
				"visibility": "public",
			},
		},
	}, job{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
	})
	if err != nil {
		t.Fatalf("load disabled checks: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected disabled check to suppress findings, got %#v", findings)
	}
}

type failureDriverState struct {
	mu                 sync.Mutex
	execs              [][]driver.NamedValue
	rolledBack         bool
	disabledChecksJSON string
}

func (s *failureDriverState) failureUpdate() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.execs) == 0 {
		return "", "", ""
	}
	args := s.execs[len(s.execs)-1]
	return fmt.Sprint(args[0].Value), fmt.Sprint(args[1].Value), fmt.Sprint(args[3].Value)
}

type failureDriver struct {
	state *failureDriverState
}

func (d *failureDriver) Open(string) (driver.Conn, error) {
	return &failureConn{state: d.state}, nil
}

type failureConn struct {
	state *failureDriverState
}

func (c *failureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}

func (c *failureConn) Close() error {
	return nil
}

func (c *failureConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *failureConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &failureTx{state: c.state}, nil
}

func (c *failureConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "array_to_json(disabled_checks)") {
		disabled := c.state.disabledChecksJSON
		if disabled == "" {
			disabled = "[]"
		}
		return &singleValueRows{columns: []string{"disabled_checks"}, values: [][]driver.Value{{disabled}}}, nil
	}
	if strings.Contains(query, "INSERT INTO ingested_events") {
		return nil, errors.New("ingested event insert failed")
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

func (c *failureConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "UPDATE ingestion_jobs") {
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	c.state.mu.Lock()
	c.state.execs = append(c.state.execs, args)
	c.state.mu.Unlock()
	return driver.RowsAffected(1), nil
}

type failureTx struct {
	state *failureDriverState
}

func (tx *failureTx) Commit() error {
	return nil
}

func (tx *failureTx) Rollback() error {
	tx.state.mu.Lock()
	tx.state.rolledBack = true
	tx.state.mu.Unlock()
	return nil
}

type singleValueRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *singleValueRows) Columns() []string {
	return r.columns
}

func (r *singleValueRows) Close() error {
	return nil
}

func (r *singleValueRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
