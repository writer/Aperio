package bootstrap

import (
	"testing"

	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
)

func TestSecurityAssetFromMapReadsProtoJSONSnakeCase(t *testing.T) {
	data := protoJSON(&aperiov1.SecurityAsset{
		Id:                    "asset_1",
		Type:                  "REPOSITORY",
		Provider:              "GITHUB",
		Name:                  "writer/aperio",
		Summary:               "source repository",
		ExternalId:            "repo_123",
		Labels:                []string{"source", "prod"},
		Criticality:           "HIGH",
		ExposureLevel:         "PUBLIC",
		OwnershipStatus:       "UNASSIGNED",
		ContainsSensitiveData: true,
		IsPrivileged:          true,
		RiskScore:             91,
		LastObservedAt:        "2026-06-06T08:00:00Z",
		CreatedAt:             "2026-06-06T08:01:00Z",
		UpdatedAt:             "2026-06-06T08:02:00Z",
		Integration:           &aperiov1.FindingIntegration{Id: "int_1", Provider: "GITHUB", DisplayName: "GitHub"},
		Owner:                 &aperiov1.SecurityPrincipal{Id: "usr_1", Email: "owner@example.com", DisplayName: "Owner"},
		BusinessOwner:         &aperiov1.SecurityPrincipal{Id: "usr_2", Email: "business@example.com", DisplayName: "Business Owner"},
		OpenFindingCount:      3,
		ActiveExceptionCount:  2,
	})

	asset := securityAssetFromMap(data)
	if asset.ExternalId != "repo_123" || asset.ExposureLevel != "PUBLIC" || asset.OwnershipStatus != "UNASSIGNED" {
		t.Fatalf("multi-word string fields were not preserved: %#v", asset)
	}
	if !asset.ContainsSensitiveData || !asset.IsPrivileged || asset.RiskScore != 91 {
		t.Fatalf("risk fields were not preserved: %#v", asset)
	}
	if asset.LastObservedAt == "" || asset.CreatedAt == "" || asset.UpdatedAt == "" {
		t.Fatalf("timestamp fields were not preserved: %#v", asset)
	}
	if asset.Integration == nil || asset.Integration.DisplayName != "GitHub" {
		t.Fatalf("integration display name was not preserved: %#v", asset.Integration)
	}
	if asset.BusinessOwner == nil || asset.BusinessOwner.DisplayName != "Business Owner" {
		t.Fatalf("business owner was not preserved: %#v", asset.BusinessOwner)
	}
	if asset.OpenFindingCount != 3 || asset.ActiveExceptionCount != 2 {
		t.Fatalf("count fields were not preserved: %#v", asset)
	}
}

func TestRiskExceptionFromMapReadsProtoJSONSnakeCase(t *testing.T) {
	data := protoJSON(&aperiov1.RiskException{
		Id:                   "exc_1",
		Title:                "Approved exposure",
		Rationale:            "temporary exception",
		CompensatingControls: []string{"reviewed weekly", "monitored"},
		Status:               "ACTIVE",
		ExpiresAt:            "2026-06-07T08:00:00Z",
		ApprovedAt:           "2026-06-06T08:00:00Z",
		CreatedAt:            "2026-06-06T07:00:00Z",
		UpdatedAt:            "2026-06-06T08:30:00Z",
		Asset:                &aperiov1.RiskExceptionAsset{Id: "asset_1", Name: "writer/aperio", Type: "REPOSITORY"},
		Finding:              &aperiov1.RiskExceptionFinding{Id: "fnd_1", Title: "Public repository", Severity: "CRITICAL", Status: "OPEN"},
		CreatedBy:            &aperiov1.SecurityPrincipal{Id: "usr_1", Email: "creator@example.com", DisplayName: "Creator"},
		ApprovedBy:           &aperiov1.SecurityPrincipal{Id: "usr_2", Email: "approver@example.com", DisplayName: "Approver"},
	})

	exception := riskExceptionFromMap(data)
	if len(exception.CompensatingControls) != 2 || exception.CompensatingControls[1] != "monitored" {
		t.Fatalf("compensating controls were not preserved: %#v", exception)
	}
	if exception.ExpiresAt == "" || exception.ApprovedAt == "" || exception.CreatedAt == "" || exception.UpdatedAt == "" {
		t.Fatalf("timestamp fields were not preserved: %#v", exception)
	}
	if exception.CreatedBy == nil || exception.CreatedBy.DisplayName != "Creator" {
		t.Fatalf("created_by principal was not preserved: %#v", exception.CreatedBy)
	}
	if exception.ApprovedBy == nil || exception.ApprovedBy.DisplayName != "Approver" {
		t.Fatalf("approved_by principal was not preserved: %#v", exception.ApprovedBy)
	}
}
