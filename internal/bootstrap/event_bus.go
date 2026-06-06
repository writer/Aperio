package bootstrap

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	aperiocontractsv1 "github.com/writer/aperio/gen/aperio/contracts/v1"
	cerebrov1 "github.com/writer/aperio/gen/cerebro/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	aperioEventSourceID              = "aperio"
	findingLifecycleSchemaRef        = "aperio/finding_lifecycle/v1"
	findingResolvedEventKind         = "aperio.finding.resolved"
	defaultAperioNATSURL             = "nats://127.0.0.1:4222"
	defaultAperioNATSStream          = "CEREBRO_EVENTS"
	aperioEventPublishConnectTimeout = 5 * time.Second
)

type encodedAperioEvent struct {
	id      string
	subject string
	payload []byte
}

func (a *App) publishFindingLifecycleEvent(ctx context.Context, findingID, organizationID, integrationID, previousStatus, nextStatus, actorUserID, resolutionNote string, occurredAt time.Time) {
	event, err := encodeFindingLifecycleEvent(findingID, organizationID, integrationID, previousStatus, nextStatus, actorUserID, resolutionNote, occurredAt)
	if err != nil {
		return
	}
	_ = publishAperioEvent(ctx, event)
}

func encodeFindingLifecycleEvent(findingID, organizationID, integrationID, previousStatus, nextStatus, actorUserID, resolutionNote string, occurredAt time.Time) (encodedAperioEvent, error) {
	eventID := compatID("evt")
	timestamp := timestamppb.New(occurredAt)
	lifecyclePayload, err := proto.Marshal(&aperiocontractsv1.FindingLifecycleEvent{
		FindingId:      findingID,
		OrganizationId: organizationID,
		IntegrationId:  integrationID,
		PreviousStatus: previousStatus,
		NextStatus:     nextStatus,
		ActorUserId:    actorUserID,
		StatusSource:   "user",
		OccurredAt:     timestamp,
		ResolutionNote: resolutionNote,
	})
	if err != nil {
		return encodedAperioEvent{}, err
	}
	kind := findingResolvedEventKind
	envelopePayload, err := proto.Marshal(&cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   organizationID,
		SourceId:   aperioEventSourceID,
		Kind:       kind,
		OccurredAt: timestamp,
		SchemaRef:  findingLifecycleSchemaRef,
		Payload:    lifecyclePayload,
		Attributes: compactEventAttributes(map[string]string{
			"finding_id":      findingID,
			"integration_id":  integrationID,
			"previous_status": previousStatus,
			"next_status":     nextStatus,
			"actor_user_id":   actorUserID,
			"status_source":   "user",
		}),
	})
	if err != nil {
		return encodedAperioEvent{}, err
	}
	return encodedAperioEvent{
		id:      eventID,
		subject: "events." + kind,
		payload: envelopePayload,
	}, nil
}

func publishAperioEvent(ctx context.Context, event encodedAperioEvent) error {
	if strings.ToLower(strings.TrimSpace(os.Getenv("APERIO_EVENT_BUS"))) != "nats" {
		return nil
	}
	servers := strings.TrimSpace(os.Getenv("APERIO_NATS_URL"))
	if servers == "" {
		servers = defaultAperioNATSURL
	}
	streamName := strings.TrimSpace(os.Getenv("APERIO_NATS_STREAM"))
	if streamName == "" {
		streamName = defaultAperioNATSStream
	}
	nc, err := nats.Connect(servers, nats.Timeout(aperioEventPublishConnectTimeout))
	if err != nil {
		return err
	}
	defer nc.Close()
	js, err := nc.JetStream(nats.Context(ctx))
	if err != nil {
		return err
	}
	if _, err := js.StreamInfo(streamName); err != nil {
		_, _ = js.AddStream(&nats.StreamConfig{Name: streamName, Subjects: []string{"events.>"}})
	}
	_, err = js.Publish(event.subject, event.payload, nats.MsgId(event.id), nats.Context(ctx))
	return err
}

func compactEventAttributes(attributes map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attributes {
		if value != "" {
			out[key] = value
		}
	}
	return out
}
