package siemdispatcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const localCaptureEnv = "APERIO_SIEM_LOCAL_CAPTURE_URL"

type localCaptureRoundTripper struct {
	endpoint string
	client   *http.Client
}

func localCaptureFromEnv() (*http.Client, func(context.Context, string) error, bool, error) {
	endpoint := strings.TrimSpace(os.Getenv(localCaptureEnv))
	if endpoint == "" {
		return nil, nil, false, nil
	}
	client, check, err := localCaptureFromURL(endpoint)
	if err != nil {
		return nil, nil, false, err
	}
	return client, check, true, nil
}

func localCaptureFromURL(endpoint string) (*http.Client, func(context.Context, string) error, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return nil, nil, errors.New("local SIEM capture URL must be an absolute http URL")
	}
	host := normalizeHostname(parsed.Hostname())
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, nil, errors.New("local SIEM capture URL must target loopback")
	}
	client := &http.Client{
		Timeout: networkTimeout,
		Transport: localCaptureRoundTripper{
			endpoint: parsed.String(),
			client:   &http.Client{Timeout: networkTimeout},
		},
	}
	return client, localCaptureEndpointSafetyCheck, nil
}

func localCaptureEndpointSafetyCheck(_ context.Context, endpoint string) error {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("local SIEM capture endpoints must be absolute HTTPS URLs")
	}
	if parsed.User != nil {
		return errors.New("local SIEM capture endpoints must not include credentials")
	}
	host := normalizeHostname(parsed.Hostname())
	if host == "" || host == "aperio.test" || !strings.HasSuffix(host, ".aperio.test") {
		return errors.New("local SIEM capture endpoints must use synthetic .aperio.test hosts")
	}
	return nil
}

func (t localCaptureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if req.Body != nil {
		_ = req.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	headers := map[string][]string{}
	for key, values := range req.Header {
		headers[key] = append([]string(nil), values...)
	}
	captureBody, err := json.Marshal(map[string]any{
		"method":     req.Method,
		"url":        req.URL.String(),
		"headers":    headers,
		"bodyBase64": base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		return nil, err
	}
	captureReq, err := http.NewRequestWithContext(
		req.Context(),
		http.MethodPost,
		t.endpoint,
		bytes.NewReader(captureBody),
	)
	if err != nil {
		return nil, err
	}
	captureReq.Header.Set("content-type", "application/json")
	captureResp, err := t.client.Do(captureReq)
	if err != nil {
		return nil, err
	}
	defer captureResp.Body.Close()
	_, _ = io.Copy(io.Discard, captureResp.Body)
	if captureResp.StatusCode < http.StatusOK || captureResp.StatusCode >= http.StatusMultipleChoices {
		return &http.Response{
			StatusCode: captureResp.StatusCode,
			Status:     captureResp.Status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}, nil
}

func EnableLocalCaptureFromEnv(d *Dispatcher) (bool, error) {
	client, check, ok, err := localCaptureFromEnv()
	if err != nil || !ok {
		return ok, err
	}
	d.SetHTTPClientForTesting(client)
	d.SetEndpointSafetyCheckForTesting(check)
	return true, nil
}

func LocalCaptureEnvNameForTesting() string {
	return localCaptureEnv
}
