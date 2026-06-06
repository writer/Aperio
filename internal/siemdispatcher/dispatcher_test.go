package siemdispatcher

import "testing"

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
