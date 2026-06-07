package bootstrap

import (
	"database/sql"
	"testing"
	"time"
)

func TestComputeSecurityOverview(t *testing.T) {
	now := time.Now()

	identities := []overviewIdentity{
		{
			ID:                  "u1",
			IntegrationID:       "int1",
			Provider:            "SALESFORCE",
			ExternalID:          "alice@example.com",
			Email:               "alice@example.com",
			DisplayName:         "Alice Admin",
			Kind:                "USER",
			Status:              "ACTIVE",
			Role:                "Administrator",
			LinkedAssetIDs:      []string{"data1"},
			MfaEnabled:          sql.NullBool{Bool: false, Valid: true},
			IsPrivileged:        true,
			IntegrationProvider: "SALESFORCE",
			IntegrationName:     "Salesforce Prod",
		},
		{
			ID:          "u2",
			Provider:    "SALESFORCE",
			ExternalID:  "bob@example.com",
			Email:       "bob@example.com",
			DisplayName: "Bob User",
			Kind:        "USER",
			Status:      "ACTIVE",
			RiskScore:   40,
		},
	}

	assets := []securityAssetRow{
		{ID: "appAsset", Type: "APPLICATION", Name: "Salesforce App", IntegrationID: "int1", RiskScore: 60, OwnershipStatus: "ASSIGNED", OwnerID: "owner1", OwnerEmail: "owner@example.com", ExposureLevel: "INTERNAL", Criticality: "MEDIUM"},
		{ID: "oauth1", Type: "OAUTH_APP", Name: "Risky OAuth", IntegrationID: "int1", RiskScore: 80, IsPrivileged: true, OwnershipStatus: "UNASSIGNED", ExposureLevel: "INTERNAL", Criticality: "HIGH"},
		{ID: "data1", Type: "DATA_RESOURCE", Name: "Customer DB", IntegrationID: "int1", RiskScore: 50, ContainsSensitiveData: true, ExposureLevel: "PUBLIC", OwnershipStatus: "ASSIGNED", Criticality: "HIGH"},
	}

	findings := []overviewFinding{
		{ID: "f1", Title: "Public data exposure", RiskScore: 70, IntegrationID: "int1", IntegrationName: "Salesforce Prod", AssetID: "data1"},
		{ID: "f2", Title: "Forwarding enabled", RiskScore: 30, IntegrationID: "int2", IntegrationName: "Workspace", RuleID: "google_workspace.email_forwarding_enabled"},
	}

	exceptions := []riskExceptionRow{
		{ID: "e1", Title: "Accepted risk", Status: "ACTIVE", CreatedAt: now, UpdatedAt: now},
		{ID: "e2", Title: "Expired", Status: "ACTIVE", ExpiresAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, CreatedAt: now, UpdatedAt: now},
	}

	googleIntegrations := []overviewGoogleIntegration{
		{ID: "int2", Provider: "GOOGLE_WORKSPACE", DisplayName: "Workspace", ExternalAccountID: "example.com", Status: "CONNECTED", Mode: "READ_ONLY", CreatedAt: now, MailboxClientEmail: "svc@example.iam.gserviceaccount.com", HasMailboxKey: true},
	}

	result := computeSecurityOverview(identities, assets, exceptions, findings, googleIntegrations)

	summary := result["summary"].(map[string]any)
	if summary["privilegedIdentities"].(int) != 1 {
		t.Fatalf("privilegedIdentities = %v, want 1", summary["privilegedIdentities"])
	}
	if summary["adminIdentitiesWithoutMfa"].(int) != 1 {
		t.Fatalf("adminIdentitiesWithoutMfa = %v, want 1", summary["adminIdentitiesWithoutMfa"])
	}
	if summary["riskyOauthApps"].(int) != 1 {
		t.Fatalf("riskyOauthApps = %v, want 1", summary["riskyOauthApps"])
	}
	if summary["exposedDataAssets"].(int) != 1 {
		t.Fatalf("exposedDataAssets = %v, want 1", summary["exposedDataAssets"])
	}
	if summary["unownedAssets"].(int) != 2 {
		t.Fatalf("unownedAssets = %v, want 2", summary["unownedAssets"])
	}
	if summary["activeExceptions"].(int) != 1 {
		t.Fatalf("activeExceptions = %v, want 1", summary["activeExceptions"])
	}
	if summary["topBlastRadiusScore"].(int) != 100 {
		t.Fatalf("topBlastRadiusScore = %v, want 100", summary["topBlastRadiusScore"])
	}

	identitiesJSON := result["identities"].([]any)
	if len(identitiesJSON) != 2 {
		t.Fatalf("identities length = %d, want 2", len(identitiesJSON))
	}
	top := identitiesJSON[0].(map[string]any)
	if top["entityId"].(string) != "u1" {
		t.Fatalf("top identity = %v, want u1", top["entityId"])
	}
	if top["riskScore"].(int) != 81 {
		t.Fatalf("u1 riskScore = %v, want 81", top["riskScore"])
	}
	if top["linkedAssetCount"].(int) != 2 {
		t.Fatalf("u1 linkedAssetCount = %v, want 2", top["linkedAssetCount"])
	}
	if top["mfaEnabled"].(bool) != false {
		t.Fatalf("u1 mfaEnabled = %v, want false", top["mfaEnabled"])
	}

	attackPaths := result["attackPaths"].([]map[string]any)
	if len(attackPaths) != 1 {
		t.Fatalf("attackPaths length = %d, want 1", len(attackPaths))
	}
	path := attackPaths[0]
	if path["score"].(int) != 100 {
		t.Fatalf("attack path score = %v, want 100", path["score"])
	}
	if path["target"].(string) != "Customer DB" {
		t.Fatalf("attack path target = %v, want Customer DB", path["target"])
	}
	if path["entryPoint"].(string) != "Alice Admin" {
		t.Fatalf("attack path entryPoint = %v, want Alice Admin", path["entryPoint"])
	}
	pathHops := path["path"].([]string)
	if len(pathHops) != 4 {
		t.Fatalf("attack path hops = %v, want 4 hops", pathHops)
	}

	graph := result["graph"].(map[string]any)
	edges := graph["edges"].([]any)
	identityEdges := 0
	assetEdges := 0
	for _, raw := range edges {
		edge := raw.(map[string]any)
		switch edge["relationshipType"].(string) {
		case "privileged_access", "access":
			identityEdges++
		default:
			assetEdges++
		}
	}
	if identityEdges != 2 {
		t.Fatalf("identity edges = %d, want 2", identityEdges)
	}
	if assetEdges != 2 {
		t.Fatalf("asset edges = %d, want 2", assetEdges)
	}

	delegations := result["domainWideDelegations"].([]map[string]any)
	if len(delegations) != 1 {
		t.Fatalf("domainWideDelegations length = %d, want 1", len(delegations))
	}
	dwd := delegations[0]
	if dwd["status"].(string) != "ENABLED" {
		t.Fatalf("dwd status = %v, want ENABLED", dwd["status"])
	}
	if dwd["openMailboxFindings"].(int) != 1 {
		t.Fatalf("dwd openMailboxFindings = %v, want 1", dwd["openMailboxFindings"])
	}
	if scopes := dwd["scopes"].([]string); len(scopes) != 2 {
		t.Fatalf("dwd scopes = %v, want 2", scopes)
	}
}

func TestSecurityOverviewPreservesUnknownMFAState(t *testing.T) {
	result := computeSecurityOverview(
		[]overviewIdentity{
			{
				ID:           "unknown-mfa",
				Provider:     "GOOGLE_WORKSPACE",
				ExternalID:   "unknown@example.com",
				Email:        "unknown@example.com",
				DisplayName:  "Unknown MFA Admin",
				Kind:         "USER",
				Status:       "ACTIVE",
				Role:         "Administrator",
				IsPrivileged: true,
			},
		},
		nil,
		nil,
		nil,
		nil,
	)

	summary := result["summary"].(map[string]any)
	if summary["adminIdentitiesWithoutMfa"].(int) != 0 {
		t.Fatalf("unknown MFA counted as disabled: %v", summary["adminIdentitiesWithoutMfa"])
	}
	identitiesJSON := result["identities"].([]any)
	identity := identitiesJSON[0].(map[string]any)
	if identity["mfaEnabled"] != nil {
		t.Fatalf("unknown MFA mfaEnabled = %v, want nil", identity["mfaEnabled"])
	}

	proto := securityOverviewFromMap(result)
	if len(proto.Identities) != 1 {
		t.Fatalf("proto identities length = %d, want 1", len(proto.Identities))
	}
	if proto.Identities[0].MfaEnabledState != nil {
		t.Fatalf("proto unknown MFA = %v, want nil", proto.Identities[0].MfaEnabledState)
	}
}

func TestSecurityOverviewFromMapPreservesExplicitMFAFalse(t *testing.T) {
	proto := securityOverviewFromMap(map[string]any{
		"summary": map[string]any{},
		"identities": []map[string]any{
			{
				"id":               "identity:u1",
				"entityId":         "u1",
				"kind":             "USER",
				"name":             "Disabled MFA Admin",
				"role":             "Administrator",
				"privileged":       true,
				"mfaEnabled":       false,
				"status":           "ACTIVE",
				"isExternal":       false,
				"linkedAssetCount": 0,
				"riskScore":        80,
			},
		},
		"graph":                 map[string]any{"nodes": []any{}, "edges": []any{}},
		"oauthApps":             []any{},
		"dataAssets":            []any{},
		"attackPaths":           []any{},
		"ownershipGaps":         []any{},
		"exceptions":            []any{},
		"domainWideDelegations": []any{},
	})

	if len(proto.Identities) != 1 {
		t.Fatalf("proto identities length = %d, want 1", len(proto.Identities))
	}
	if proto.Identities[0].MfaEnabledState == nil || *proto.Identities[0].MfaEnabledState {
		t.Fatalf("proto explicit disabled MFA = %v, want false", proto.Identities[0].MfaEnabledState)
	}
}
