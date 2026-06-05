package telemetry

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"
)

type contextKey struct{}

type Field struct {
	Key   string
	Value any
}

type Attributes struct {
	values map[string]any
}

type WideEvent struct {
	Name         string
	Organization string
	Service      string
	Dimensions   map[string]string
	Measurements map[string]int64
}

func Attrs(fields ...Field) Attributes {
	attrs := Attributes{values: map[string]any{}}
	for _, field := range fields {
		if field.Key != "" {
			attrs.values[field.Key] = field.Value
		}
	}
	return attrs
}

func WithOrganization(ctx context.Context, organizationID string) context.Context {
	return context.WithValue(ctx, contextKey{}, organizationID)
}

func Organization(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{}).(string)
	return value
}

func Event(name string, attrs Attributes) {
	payload := map[string]any{
		"kind":       "event",
		"event_name": name,
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	}
	for key, value := range attrs.values {
		payload[key] = value
	}
	write(payload)
}

func EmitWide(event WideEvent) {
	payload := map[string]any{
		"kind":        "wide_event",
		"event_name":  event.Name,
		"service":     event.Service,
		"occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if event.Organization != "" {
		payload["organization_id"] = event.Organization
	}
	for key, value := range event.Dimensions {
		payload[key] = value
	}
	for key, value := range event.Measurements {
		payload[key] = value
	}
	write(payload)
}

func write(payload map[string]any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("telemetry encode: %v", err)
		return
	}
	encoded = append(encoded, '\n')
	if _, err := os.Stderr.Write(encoded); err != nil {
		log.Printf("telemetry write: %v", err)
	}
}
