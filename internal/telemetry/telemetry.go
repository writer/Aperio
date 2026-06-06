package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type contextKey struct{}

type collectorKey struct{}

// Collector accumulates wide-event annotations for a single unit of work. The
// wide-event interceptor stores a pointer in the request context so handlers can
// enrich the one event emitted per RPC without each re-plumbing timing, status,
// or emission. It is safe for concurrent use.
type Collector struct {
	mu           sync.Mutex
	organization string
	dimensions   map[string]string
	measurements map[string]int64
}

// NewCollector returns a context carrying a fresh Collector and the Collector
// itself, so the caller (the interceptor) can read the accumulated annotations
// after the handler returns.
func NewCollector(ctx context.Context) (context.Context, *Collector) {
	collector := &Collector{
		dimensions:   map[string]string{},
		measurements: map[string]int64{},
	}
	return context.WithValue(ctx, collectorKey{}, collector), collector
}

// CollectorFrom returns the Collector attached to ctx, if any. Handlers should
// tolerate its absence so they remain callable from tests and non-RPC paths.
func CollectorFrom(ctx context.Context) (*Collector, bool) {
	collector, ok := ctx.Value(collectorKey{}).(*Collector)
	return collector, ok
}

// SetOrganization records the tenant boundary once authentication resolves it.
func (c *Collector) SetOrganization(organization string) {
	if c == nil || strings.TrimSpace(organization) == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.organization = organization
}

// Dimension records a low-cardinality string attribute. Empty values are
// ignored so the emitted event matches the previous "non-empty only" behavior.
func (c *Collector) Dimension(key, value string) {
	if c == nil || key == "" || strings.TrimSpace(value) == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dimensions[key] = value
}

// Measurement records a numeric attribute (counts, sizes, durations).
func (c *Collector) Measurement(key string, value int64) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.measurements[key] = value
}

// Snapshot returns copies of the accumulated annotations that are safe to read
// after the handler returns.
func (c *Collector) Snapshot() (organization string, dimensions map[string]string, measurements map[string]int64) {
	if c == nil {
		return "", nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dimensions = make(map[string]string, len(c.dimensions))
	for key, value := range c.dimensions {
		dimensions[key] = value
	}
	measurements = make(map[string]int64, len(c.measurements))
	for key, value := range c.measurements {
		measurements[key] = value
	}
	return c.organization, dimensions, measurements
}

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

var (
	outputMu sync.Mutex
	output   io.Writer = os.Stderr
)

// SetOutput redirects emitted telemetry to w and returns a function that
// restores the previous sink. It exists so tests can capture and assert on the
// JSON events; production always writes to stderr.
func SetOutput(w io.Writer) (restore func()) {
	outputMu.Lock()
	defer outputMu.Unlock()
	previous := output
	output = w
	return func() {
		outputMu.Lock()
		defer outputMu.Unlock()
		output = previous
	}
}

func write(payload map[string]any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("telemetry encode: %v", err)
		return
	}
	encoded = append(encoded, '\n')
	outputMu.Lock()
	sink := output
	outputMu.Unlock()
	if _, err := sink.Write(encoded); err != nil {
		log.Printf("telemetry write: %v", err)
	}
}
