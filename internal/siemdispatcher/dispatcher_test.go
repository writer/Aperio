package siemdispatcher

import (
	"database/sql"
	"errors"
	"testing"
)

func TestStableDeliveryKeyIncludesFindingOccurrence(t *testing.T) {
	payload := Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record: map[string]any{
			"dedupeKey": "stable-finding",
			"status":    "OPEN",
		},
	}
	first := StableDeliveryKey(payload, "dst_1", "FINDINGS")
	reopenedPayload := payload
	reopenedPayload.OccurredAt = "2026-06-06T01:00:00.000Z"
	reopened := StableDeliveryKey(reopenedPayload, "dst_1", "FINDINGS")
	if first == reopened {
		t.Fatal("expected reopened finding occurrence to produce a distinct key")
	}
	if first != StableDeliveryKey(payload, "dst_1", "FINDINGS") {
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
