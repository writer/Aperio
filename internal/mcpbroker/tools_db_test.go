package mcpbroker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDBBackedAgentTaskMessageToolsPreserveSeededBehavior(t *testing.T) {
	db := openMCPToolTestDB(t)
	defer db.Close()
	ctx := context.Background()
	orgID := seedMCPToolOrganization(t, db, "MCP Tools Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Other Org")
	service := NewToolService(db)

	register := callMCPToolFrame(t, service, "register-1", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "scanner",
		"name":           "Scanner Agent",
		"capabilities":   []any{" posture.scan "},
	})
	agentID := requireStringField(t, register, "agentId")
	if register["key"] != "scanner" || register["status"] != "ACTIVE" {
		t.Fatalf("register result drifted: %#v", register)
	}

	updatedRegister := callMCPToolFrame(t, service, "register-2", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "scanner",
		"name":           "Scanner Agent Renamed",
		"kind":           "SSPM_SCANNER",
		"capabilities":   []any{"posture.scan", "remediate.plan"},
		"endpointUrl":    "https://agents.example.test/scanner",
		"mcpServerUrl":   "https://agents.example.test/mcp",
		"status":         "PAUSED",
	})
	if updatedRegister["agentId"] != agentID {
		t.Fatalf("register_agent duplicate call changed id: first=%s second=%v", agentID, updatedRegister["agentId"])
	}
	if count := queryMCPInt(t, db, `SELECT COUNT(*) FROM agents WHERE organization_id = $1 AND key = 'scanner'`, orgID); count != 1 {
		t.Fatalf("register_agent created %d scanner rows, want 1", count)
	}
	assertAgentFields(t, db, agentID, "Scanner Agent Renamed", "SSPM_SCANNER", []string{"posture.scan", "remediate.plan"}, "PAUSED")

	assignee := callMCPToolFrame(t, service, "register-assignee", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "assignee",
		"name":           "Assignee Agent",
		"kind":           "REMEDIATION_PLANNER",
	})
	assigneeID := requireStringField(t, assignee, "agentId")
	otherAgent := callMCPToolFrame(t, service, "register-other-agent", "aperio.register_agent", map[string]any{
		"organizationId": otherOrgID,
		"key":            "scanner",
		"name":           "Other Tenant Scanner",
	})
	if otherAgent["agentId"] == agentID {
		t.Fatalf("same agent key in another tenant reused id %s", agentID)
	}
	_ = callMCPToolFrame(t, service, "register-other-only", "aperio.register_agent", map[string]any{
		"organizationId": otherOrgID,
		"key":            "foreign-only",
		"name":           "Foreign Only Agent",
	})

	parent := callMCPToolFrame(t, service, "create-parent", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "review",
		"title":             "Review finding",
		"input":             map[string]any{"phase": "parent"},
		"createdByAgentKey": "scanner",
		"assignedAgentKey":  "assignee",
	})
	parentID := requireStringField(t, parent, "taskId")
	if parent["status"] != "QUEUED" {
		t.Fatalf("parent task status = %v, want QUEUED", parent["status"])
	}
	child := callMCPToolFrame(t, service, "create-child", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "remediate",
		"title":             "Plan remediation",
		"input":             map[string]any{"phase": "child", "attempt": 1},
		"createdByAgentKey": "scanner",
		"assignedAgentKey":  "assignee",
		"parentTaskId":      parentID,
	})
	childID := requireStringField(t, child, "taskId")
	assertTaskReferences(t, db, childID, orgID, agentID, assigneeID, parentID)

	otherTask := callMCPToolFrame(t, service, "create-other-task", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"taskType":       "other",
		"title":          "Other tenant task",
	})
	otherTaskID := requireStringField(t, otherTask, "taskId")

	message := callMCPToolFrame(t, service, "send-message", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"taskId":         childID,
		"fromAgentKey":   "scanner",
		"toAgentKey":     "assignee",
		"correlationId":  "corr-1",
		"content":        map[string]any{"body": "ready", "ok": true},
	})
	messageID := requireStringField(t, message, "messageId")
	assertMCPISOTime(t, message["createdAt"])
	assertMessageReferences(t, db, messageID, orgID, childID, agentID, assigneeID)

	if _, err := db.ExecContext(ctx, `
		UPDATE agent_tasks
		SET status = 'SUCCEEDED'::"AgentTaskStatus", created_at = NOW() - INTERVAL '2 seconds', updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, parentID, orgID); err != nil {
		t.Fatalf("age parent task: %v", err)
	}

	all := callMCPToolFrame(t, service, "list-all", "aperio.list_tasks", map[string]any{"organizationId": orgID})
	allTasks := requireTaskList(t, all, 2)
	if allTasks[0]["id"] != childID || allTasks[1]["id"] != parentID {
		t.Fatalf("list_tasks ordering drifted: got first=%v second=%v want child=%s parent=%s", allTasks[0]["id"], allTasks[1]["id"], childID, parentID)
	}
	assertTaskResultShape(t, allTasks[0], childID, orgID, "remediate", "Plan remediation", "QUEUED", "scanner", "assignee", parentID)
	assertMCPISOTime(t, allTasks[0]["createdAt"])
	assertMCPISOTime(t, allTasks[0]["updatedAt"])

	queued := callMCPToolFrame(t, service, "list-queued-assignee", "aperio.list_tasks", map[string]any{
		"organizationId":   orgID,
		"status":           "QUEUED",
		"assignedAgentKey": "assignee",
	})
	queuedTasks := requireTaskList(t, queued, 1)
	if queuedTasks[0]["id"] != childID {
		t.Fatalf("list_tasks status/assigned filter returned %#v, want child task %s", queuedTasks, childID)
	}

	succeeded := callMCPToolFrame(t, service, "list-succeeded", "aperio.list_tasks", map[string]any{
		"organizationId": orgID,
		"status":         "SUCCEEDED",
	})
	succeededTasks := requireTaskList(t, succeeded, 1)
	if succeededTasks[0]["id"] != parentID {
		t.Fatalf("list_tasks status filter returned %#v, want parent task %s", succeededTasks, parentID)
	}

	if tasks := callMCPToolFrame(t, service, "list-other-org", "aperio.list_tasks", map[string]any{"organizationId": otherOrgID})["tasks"].([]any); len(tasks) != 1 || tasks[0].(map[string]any)["id"] != otherTaskID {
		t.Fatalf("cross-tenant task data leaked or disappeared: %#v", tasks)
	}

	beforeTasks := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_tasks WHERE organization_id = $1`, orgID)
	beforeMessages := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_messages WHERE organization_id = $1`, orgID)
	expectMCPToolErrorFrame(t, service, "bad-cross-agent", "aperio.create_task", map[string]any{
		"organizationId":   orgID,
		"taskType":         "review",
		"title":            "Bad cross tenant assignment",
		"assignedAgentKey": "foreign-only",
	})
	expectMCPToolErrorFrame(t, service, "bad-cross-task", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"taskId":         otherTaskID,
		"content":        map[string]any{"body": "must fail"},
	})
	expectMCPToolErrorFrame(t, service, "bad-list-cross-agent", "aperio.list_tasks", map[string]any{
		"organizationId":   orgID,
		"assignedAgentKey": "foreign-only",
	})
	if afterTasks := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_tasks WHERE organization_id = $1`, orgID); afterTasks != beforeTasks {
		t.Fatalf("invalid cross-tenant task reference changed task count from %d to %d", beforeTasks, afterTasks)
	}
	if afterMessages := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_messages WHERE organization_id = $1`, orgID); afterMessages != beforeMessages {
		t.Fatalf("invalid cross-tenant task reference changed message count from %d to %d", beforeMessages, afterMessages)
	}
}

func TestDBBackedRemediationProposalsStayHumanGated(t *testing.T) {
	db := openMCPToolTestDB(t)
	defer db.Close()
	orgID := seedMCPToolOrganization(t, db, "MCP Proposal Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Proposal Other Org")
	service := NewToolService(db)

	agent := callMCPToolFrame(t, service, "proposal-agent", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "planner",
		"name":           "Planner Agent",
	})
	agentID := requireStringField(t, agent, "agentId")
	task := callMCPToolFrame(t, service, "proposal-task", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "remediation",
		"title":             "Draft remediation",
		"createdByAgentKey": "planner",
	})
	taskID := requireStringField(t, task, "taskId")
	_, findingID := seedMCPFinding(t, db, orgID, "proposal")
	_, otherFindingID := seedMCPFinding(t, db, otherOrgID, "other-proposal")
	otherTask := callMCPToolFrame(t, service, "other-proposal-task", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"taskType":       "other",
		"title":          "Other proposal task",
	})
	otherTaskID := requireStringField(t, otherTask, "taskId")

	beforeProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id = $1`, orgID)
	beforeAuditLogs := queryMCPInt(t, db, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1`, orgID)
	proposal := callMCPToolFrame(t, service, "proposal", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          findingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Human approval required before revoking the app.",
		"payload":            map[string]any{"appId": "A123", "dryRun": true},
	})
	proposalID := requireStringField(t, proposal, "proposalId")
	if proposal["status"] != "PROPOSED" {
		t.Fatalf("proposal status = %v, want PROPOSED", proposal["status"])
	}
	assertProposalHumanGated(t, db, proposalID, orgID, taskID, findingID, agentID)
	if afterProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id = $1`, orgID); afterProposals != beforeProposals+1 {
		t.Fatalf("proposal count = %d, want %d", afterProposals, beforeProposals+1)
	}
	if afterAuditLogs := queryMCPInt(t, db, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1`, orgID); afterAuditLogs != beforeAuditLogs {
		t.Fatalf("proposal tool produced provider/audit side effects: before=%d after=%d", beforeAuditLogs, afterAuditLogs)
	}

	beforeAllProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id IN ($1, $2)`, orgID, otherOrgID)
	expectMCPToolErrorFrame(t, service, "proposal-cross-task", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             otherTaskID,
		"findingId":          findingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for cross-tenant task.",
		"payload":            map[string]any{"appId": "A123"},
	})
	expectMCPToolErrorFrame(t, service, "proposal-cross-finding", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          otherFindingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for cross-tenant finding.",
		"payload":            map[string]any{"appId": "A123"},
	})
	expectMCPToolErrorFrame(t, service, "proposal-missing-agent", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          findingID,
		"proposedByAgentKey": "missing-agent",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for missing proposing agent.",
		"payload":            map[string]any{"appId": "A123"},
	})
	if afterAllProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id IN ($1, $2)`, orgID, otherOrgID); afterAllProposals != beforeAllProposals {
		t.Fatalf("invalid proposal references changed proposal count from %d to %d", beforeAllProposals, afterAllProposals)
	}
}

func TestMCPSharedSecretAndTenantBoundariesRejectBeforeSideEffectsAndDoNotPersistSecrets(t *testing.T) {
	db := openMCPToolTestDB(t)
	defer db.Close()
	orgID := seedMCPToolOrganization(t, db, "MCP Secret Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Secret Other Org")
	secret := "mcp-secret-" + randomID()
	t.Setenv("APERIO_MCP_ORGANIZATION_ID", orgID)
	t.Setenv("APERIO_MCP_SHARED_SECRET", secret)
	service := NewToolService(db)

	beforeOrg := mcpSideEffectCount(t, db, orgID)
	beforeOtherOrg := mcpSideEffectCount(t, db, otherOrgID)
	missingTokenOutput := expectMCPToolErrorFrame(t, service, "missing-token", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "blocked",
		"name":           "Blocked Agent",
	})
	wrongTokenOutput := expectMCPToolErrorFrame(t, service, "wrong-token", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"authToken":      "wrong-" + randomID(),
		"key":            "blocked",
		"name":           "Blocked Agent",
	})
	wrongOrgOutput := expectMCPToolErrorFrame(t, service, "wrong-org", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"authToken":      secret,
		"taskType":       "blocked",
		"title":          "Blocked task",
	})
	for label, output := range map[string][]byte{
		"missing token": missingTokenOutput,
		"wrong token":   wrongTokenOutput,
		"wrong org":     wrongOrgOutput,
	} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("%s error frame disclosed shared secret in stdout: %q", label, string(output))
		}
	}
	if afterOrg := mcpSideEffectCount(t, db, orgID); afterOrg != beforeOrg {
		t.Fatalf("auth failures changed scoped side effects from %d to %d", beforeOrg, afterOrg)
	}
	if afterOtherOrg := mcpSideEffectCount(t, db, otherOrgID); afterOtherOrg != beforeOtherOrg {
		t.Fatalf("wrong-organization call changed other tenant side effects from %d to %d", beforeOtherOrg, afterOtherOrg)
	}

	agent := callMCPToolFrame(t, service, "secret-register", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"authToken":      secret,
		"key":            "secret-agent",
		"name":           "Secret Scoped Agent",
	})
	agentID := requireStringField(t, agent, "agentId")
	task := callMCPToolFrame(t, service, "secret-task", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"authToken":         secret,
		"taskType":          "secret-safe",
		"title":             "Secret-safe task",
		"input":             map[string]any{"note": "auth token must not be copied"},
		"createdByAgentKey": "secret-agent",
	})
	taskID := requireStringField(t, task, "taskId")
	message := callMCPToolFrame(t, service, "secret-message", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"authToken":      secret,
		"taskId":         taskID,
		"fromAgentKey":   "secret-agent",
		"content":        map[string]any{"body": "safe content"},
	})
	_ = requireStringField(t, message, "messageId")
	proposal := callMCPToolFrame(t, service, "secret-proposal", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"authToken":          secret,
		"taskId":             taskID,
		"proposedByAgentKey": "secret-agent",
		"action":             "manual.review",
		"rationale":          "Human-gated proposal with no copied auth token.",
		"payload":            map[string]any{"ticket": "SEC-1"},
	})
	_ = requireStringField(t, proposal, "proposalId")
	if agentID == "" || taskID == "" {
		t.Fatalf("valid secret-scoped calls did not produce ids")
	}
	assertMCPSecretNotPersisted(t, db, orgID, secret)
}

func openMCPToolTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("APERIO_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open MCP test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping MCP test database: %v", err)
	}
	return db
}

func seedMCPToolOrganization(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	orgID := prefixedID("org")
	slug := "mcp-tools-" + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, name, slug); err != nil {
		t.Fatalf("seed MCP organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID
}

func seedMCPFinding(t *testing.T, db *sql.DB, orgID string, suffix string) (string, string) {
	t.Helper()
	integrationID := prefixedID("int")
	findingID := prefixedID("fnd")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, status, mode, created_at, updated_at
		)
		VALUES (
			$1, $2, 'SLACK'::"SaaSProvider", $3, $4, ARRAY[]::text[], ARRAY[]::text[],
			'test-token-envelope', 'CONNECTED'::"IntegrationStatus", 'REMEDIATION'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID, "MCP Slack "+suffix, "mcp-"+suffix+"-"+strings.ToLower(randomID())); err != nil {
		t.Fatalf("seed MCP integration: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at
		)
		VALUES (
			$1, $2, $3, $4, 'Seeded MCP finding', 'Seeded for MCP proposal tests',
			'HIGH'::"Severity", 'OPEN'::"FindingStatus", 70, ARRAY['Review manually']::text[],
			'{"subject":"A123"}'::jsonb, NOW()
		)
	`, findingID, orgID, integrationID, "mcp-"+suffix+"-"+strings.ToLower(randomID())); err != nil {
		t.Fatalf("seed MCP finding: %v", err)
	}
	return integrationID, findingID
}

func callMCPToolFrame(t *testing.T, service *ToolService, id string, name string, args map[string]any) map[string]any {
	t.Helper()
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, toolCall(id, name, args))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("tool call %s returned %d frames, want 1", id, len(frames))
	}
	result := frames[0]["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("tool call %s unexpectedly failed: %#v", id, result)
	}
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("tool call %s returned non-JSON content %q: %v", id, text, err)
	}
	return parsed
}

func expectMCPToolErrorFrame(t *testing.T, service *ToolService, id string, name string, args map[string]any) []byte {
	t.Helper()
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, toolCall(id, name, args))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("tool call %s returned %d frames, want 1", id, len(frames))
	}
	result := frames[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("tool call %s succeeded, want MCP isError result: %#v", id, result)
	}
	content := result["content"].([]any)
	if text := content[0].(map[string]any)["text"].(string); strings.TrimSpace(text) == "" {
		t.Fatalf("tool call %s returned empty error text: %#v", id, result)
	}
	return stdout
}

func requireStringField(t *testing.T, values map[string]any, field string) string {
	t.Helper()
	value, ok := values[field].(string)
	if !ok || strings.TrimSpace(value) == "" {
		t.Fatalf("field %s = %#v, want non-empty string in %#v", field, values[field], values)
	}
	return value
}

func requireTaskList(t *testing.T, result map[string]any, want int) []map[string]any {
	t.Helper()
	raw, ok := result["tasks"].([]any)
	if !ok {
		t.Fatalf("tasks = %#v, want array", result["tasks"])
	}
	if len(raw) != want {
		t.Fatalf("tasks length = %d, want %d: %#v", len(raw), want, raw)
	}
	tasks := make([]map[string]any, len(raw))
	for index, item := range raw {
		task, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("tasks[%d] = %#v, want object", index, item)
		}
		tasks[index] = task
	}
	return tasks
}

func queryMCPInt(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatalf("query int: %v\n%s", err, query)
	}
	return count
}

func assertAgentFields(t *testing.T, db *sql.DB, agentID string, wantName string, wantKind string, wantCapabilities []string, wantStatus string) {
	t.Helper()
	var name, kind, capabilitiesJSON, status string
	var endpointURL, mcpServerURL sql.NullString
	var hasLastSeen bool
	if err := db.QueryRowContext(context.Background(), `
		SELECT name, kind::text, to_json(capabilities)::text, endpoint_url, mcp_server_url, status::text, last_seen_at IS NOT NULL
		FROM agents
		WHERE id = $1
	`, agentID).Scan(&name, &kind, &capabilitiesJSON, &endpointURL, &mcpServerURL, &status, &hasLastSeen); err != nil {
		t.Fatalf("query agent fields: %v", err)
	}
	var capabilities []string
	if err := json.Unmarshal([]byte(capabilitiesJSON), &capabilities); err != nil {
		t.Fatalf("decode capabilities %q: %v", capabilitiesJSON, err)
	}
	if name != wantName || kind != wantKind || status != wantStatus || !hasLastSeen {
		t.Fatalf("agent fields drifted: name=%s kind=%s status=%s hasLastSeen=%v", name, kind, status, hasLastSeen)
	}
	if strings.Join(capabilities, ",") != strings.Join(wantCapabilities, ",") {
		t.Fatalf("capabilities = %#v, want %#v", capabilities, wantCapabilities)
	}
	if endpointURL.String != "https://agents.example.test/scanner" || mcpServerURL.String != "https://agents.example.test/mcp" {
		t.Fatalf("agent URLs drifted: endpoint=%#v mcp=%#v", endpointURL, mcpServerURL)
	}
}

func assertTaskReferences(t *testing.T, db *sql.DB, taskID string, orgID string, createdByAgentID string, assignedAgentID string, parentTaskID string) {
	t.Helper()
	var gotOrgID, status, gotCreatedBy, gotAssigned, gotParent, inputJSON string
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, status::text, created_by_agent_id, assigned_agent_id, parent_task_id, input::text
		FROM agent_tasks
		WHERE id = $1
	`, taskID).Scan(&gotOrgID, &status, &gotCreatedBy, &gotAssigned, &gotParent, &inputJSON); err != nil {
		t.Fatalf("query task references: %v", err)
	}
	if gotOrgID != orgID || status != "QUEUED" || gotCreatedBy != createdByAgentID || gotAssigned != assignedAgentID || gotParent != parentTaskID {
		t.Fatalf("task references drifted: org=%s status=%s created=%s assigned=%s parent=%s", gotOrgID, status, gotCreatedBy, gotAssigned, gotParent)
	}
	if !strings.Contains(inputJSON, `"phase": "child"`) && !strings.Contains(inputJSON, `"phase":"child"`) {
		t.Fatalf("task input not persisted as JSON object: %s", inputJSON)
	}
}

func assertMessageReferences(t *testing.T, db *sql.DB, messageID string, orgID string, taskID string, fromAgentID string, toAgentID string) {
	t.Helper()
	var gotOrgID, gotTaskID, gotFromAgentID, gotToAgentID, role, messageType, correlationID, contentJSON string
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, task_id, from_agent_id, to_agent_id, role::text, message_type, correlation_id, content::text
		FROM agent_messages
		WHERE id = $1
	`, messageID).Scan(&gotOrgID, &gotTaskID, &gotFromAgentID, &gotToAgentID, &role, &messageType, &correlationID, &contentJSON); err != nil {
		t.Fatalf("query message references: %v", err)
	}
	if gotOrgID != orgID || gotTaskID != taskID || gotFromAgentID != fromAgentID || gotToAgentID != toAgentID || role != "AGENT" || messageType != "a2a.message.v1" || correlationID != "corr-1" {
		t.Fatalf("message fields drifted: org=%s task=%s from=%s to=%s role=%s type=%s corr=%s", gotOrgID, gotTaskID, gotFromAgentID, gotToAgentID, role, messageType, correlationID)
	}
	if !strings.Contains(contentJSON, `"body": "ready"`) && !strings.Contains(contentJSON, `"body":"ready"`) {
		t.Fatalf("message content not persisted as JSON object: %s", contentJSON)
	}
}

func assertTaskResultShape(t *testing.T, task map[string]any, taskID string, orgID string, taskType string, title string, status string, createdByKey string, assignedKey string, parentTaskID string) {
	t.Helper()
	wantKeys := []string{
		"assignedAgent", "assignedAgentId", "completedAt", "createdAt", "createdByAgent", "createdByAgentId",
		"error", "id", "input", "leaseExpiresAt", "organizationId", "output", "parentTaskId", "startedAt",
		"status", "taskType", "title", "updatedAt",
	}
	for _, key := range wantKeys {
		if _, ok := task[key]; !ok {
			t.Fatalf("task result missing key %s: %#v", key, task)
		}
	}
	if len(task) != len(wantKeys) {
		t.Fatalf("task result has unexpected keys: %#v", task)
	}
	if task["id"] != taskID || task["organizationId"] != orgID || task["taskType"] != taskType || task["title"] != title || task["status"] != status || task["parentTaskId"] != parentTaskID {
		t.Fatalf("task scalar fields drifted: %#v", task)
	}
	createdBy := task["createdByAgent"].(map[string]any)
	assigned := task["assignedAgent"].(map[string]any)
	if createdBy["key"] != createdByKey || assigned["key"] != assignedKey {
		t.Fatalf("task agent summaries drifted: created=%#v assigned=%#v", createdBy, assigned)
	}
}

func assertProposalHumanGated(t *testing.T, db *sql.DB, proposalID string, orgID string, taskID string, findingID string, agentID string) {
	t.Helper()
	var gotOrgID, gotTaskID, gotFindingID, proposedByAgentID, action, status, payloadJSON string
	var approvedBy sql.NullString
	var approvedAt, executedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, task_id, finding_id, proposed_by_agent_id, action, status::text,
		       approved_by_user_id, approved_at, executed_at, payload::text
		FROM agent_proposals
		WHERE id = $1
	`, proposalID).Scan(&gotOrgID, &gotTaskID, &gotFindingID, &proposedByAgentID, &action, &status, &approvedBy, &approvedAt, &executedAt, &payloadJSON); err != nil {
		t.Fatalf("query proposal: %v", err)
	}
	if gotOrgID != orgID || gotTaskID != taskID || gotFindingID != findingID || proposedByAgentID != agentID || action != "slack.revoke_app_install" || status != "PROPOSED" {
		t.Fatalf("proposal fields drifted: org=%s task=%s finding=%s proposedBy=%s action=%s status=%s", gotOrgID, gotTaskID, gotFindingID, proposedByAgentID, action, status)
	}
	if approvedBy.Valid || approvedAt.Valid || executedAt.Valid {
		t.Fatalf("proposal was not human-gated: approvedBy=%#v approvedAt=%#v executedAt=%#v", approvedBy, approvedAt, executedAt)
	}
	if !strings.Contains(payloadJSON, `"appId": "A123"`) && !strings.Contains(payloadJSON, `"appId":"A123"`) {
		t.Fatalf("proposal payload not persisted correctly: %s", payloadJSON)
	}
}

func assertMCPISOTime(t *testing.T, value any) {
	t.Helper()
	text, ok := value.(string)
	if !ok {
		t.Fatalf("timestamp = %#v, want string", value)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`).MatchString(text) {
		t.Fatalf("timestamp %q does not match JavaScript ISO millisecond shape", text)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", text); err != nil {
		t.Fatalf("timestamp %q is not parseable: %v", text, err)
	}
}

func assertMCPSecretNotPersisted(t *testing.T, db *sql.DB, orgID string, secret string) {
	t.Helper()
	var matches int
	if err := db.QueryRowContext(context.Background(), `
		SELECT
			(SELECT COUNT(*) FROM agents
			 WHERE organization_id = $1
			   AND (
			     strpos(key, $2) > 0 OR strpos(name, $2) > 0 OR
			     strpos(COALESCE(array_to_string(capabilities, E'\n'), ''), $2) > 0 OR
			     strpos(COALESCE(endpoint_url, ''), $2) > 0 OR
			     strpos(COALESCE(mcp_server_url, ''), $2) > 0
			   )) +
			(SELECT COUNT(*) FROM agent_tasks
			 WHERE organization_id = $1
			   AND (
			     strpos(input::text, $2) > 0 OR strpos(COALESCE(output::text, ''), $2) > 0 OR
			     strpos(COALESCE(error, ''), $2) > 0
			   )) +
			(SELECT COUNT(*) FROM agent_messages
			 WHERE organization_id = $1 AND strpos(content::text, $2) > 0) +
			(SELECT COUNT(*) FROM agent_proposals
			 WHERE organization_id = $1
			   AND (
			     strpos(action, $2) > 0 OR strpos(rationale, $2) > 0 OR strpos(payload::text, $2) > 0
			   )) +
			(SELECT COUNT(*) FROM siem_deliveries
			 WHERE organization_id = $1 AND strpos(payload::text, $2) > 0)
	`, orgID, secret).Scan(&matches); err != nil {
		t.Fatalf("scan MCP side-effect tables for shared secret: %v", err)
	}
	if matches != 0 {
		t.Fatalf("shared secret appeared in %d MCP side-effect rows", matches)
	}
}
