package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/gen/aperio/v1/aperiov1connect"
	"github.com/writer/aperio/internal/config"
)

func TestCheckHealthConnectEndpoint(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := aperiov1connect.NewAperioServiceClient(server.Client(), server.URL)

	resp, err := client.CheckHealth(
		context.Background(),
		connect.NewRequest(&aperiov1.CheckHealthRequest{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Status != "ok" {
		t.Fatalf("expected ok, got %s", resp.Msg.Status)
	}
}

func TestConnectCORSPreflight(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(http.MethodOptions, "/aperio.v1.AperioService/GetDashboardMetrics", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("expected matching CORS origin")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("expected credentialed CORS")
	}
}
