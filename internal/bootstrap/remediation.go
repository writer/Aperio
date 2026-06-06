package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// This file ports apps/api/src/remediation/executor.ts while progressively
// replacing simulated provider effects with real, injectable provider calls.

type remediationResult struct {
	Success           bool
	ProviderRequestID string
	Message           string
	Effects           []string
}

type remediationHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type remediationRequest struct {
	Provider          string
	Action            string
	ExternalAccountID string
	TargetIdentifier  string
	IntegrationToken  string
}

func pseudoRequestID(prefix string) string {
	return prefix + "_" + strconv.FormatInt(time.Now().UnixMilli(), 36) + "_" + randomBase36(8)
}

func randomBase36(length int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "00000000"[:length]
	}
	for index := range buffer {
		buffer[index] = alphabet[int(buffer[index])%len(alphabet)]
	}
	return string(buffer)
}

func connectorHasRemediationAction(connector *connectorDefinition, action string) bool {
	definition, ok := findRemediationActionDefinition(action)
	return ok && connector != nil && definition.Provider == connector.Provider
}

func (a *App) executeRemediation(ctx context.Context, request remediationRequest) remediationResult {
	if definition, ok := findRemediationActionDefinition(request.Action); ok && definition.Class == remediationActionUnsupported {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Action " + request.Action + " is unavailable: provider remediation is not implemented in this build",
			Effects:           []string{},
		}
	}
	switch request.Action {
	case "slack.revoke_app_install":
		return a.executeSlackRevokeAppInstall(ctx, request)
	default:
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Unknown remediation action " + request.Action,
			Effects:           []string{},
		}
	}
}

func (a *App) executeSlackRevokeAppInstall(ctx context.Context, request remediationRequest) remediationResult {
	target := strings.TrimSpace(request.TargetIdentifier)
	if target == "" {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Slack app id is required for slack.revoke_app_install",
			Effects:           []string{},
		}
	}
	token := strings.TrimSpace(request.IntegrationToken)
	if token == "" {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Slack access token is unavailable",
			Effects:           []string{},
		}
	}

	baseURL := "https://slack.com/api"
	client := remediationHTTPDoer(&http.Client{Timeout: 10 * time.Second})
	if a != nil {
		if strings.TrimSpace(a.slackAPIBaseURL) != "" {
			baseURL = a.slackAPIBaseURL
		}
		if a.remediationHTTPClient != nil {
			client = a.remediationHTTPClient
		}
	}
	endpoint, err := url.JoinPath(baseURL, "admin.apps.uninstall")
	if err != nil {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Slack API endpoint is misconfigured",
			Effects:           []string{},
		}
	}

	form := url.Values{"app_id": {target}}
	if workspace := strings.TrimSpace(request.ExternalAccountID); workspace != "" {
		form.Set("team_ids", workspace)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Slack request could not be created",
			Effects:           []string{},
		}
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return remediationResult{
			Success:           false,
			ProviderRequestID: "",
			Message:           "Slack admin.apps.uninstall request failed",
			Effects:           []string{},
		}
	}
	defer resp.Body.Close()
	requestID := strings.TrimSpace(resp.Header.Get("X-Slack-Req-Id"))
	if requestID == "" {
		requestID = pseudoRequestID("slack")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return remediationResult{
			Success:           false,
			ProviderRequestID: requestID,
			Message:           "Slack admin.apps.uninstall returned HTTP " + strconv.Itoa(resp.StatusCode),
			Effects:           []string{},
		}
	}

	var decoded struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&decoded); err != nil {
		return remediationResult{
			Success:           false,
			ProviderRequestID: requestID,
			Message:           "Slack admin.apps.uninstall returned an invalid response",
			Effects:           []string{},
		}
	}
	if !decoded.OK {
		return remediationResult{
			Success:           false,
			ProviderRequestID: requestID,
			Message:           "Slack admin.apps.uninstall failed: " + slackErrorMessage(decoded.Error),
			Effects:           []string{},
		}
	}
	return remediationResult{
		Success:           true,
		ProviderRequestID: requestID,
		Message:           "Slack app " + target + " uninstalled",
		Effects: []string{
			"admin.apps.uninstall",
			"OAuth tokens revoked",
			"Bot user removed from all channels",
		},
	}
}

func slackErrorMessage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown_error"
	}
	if len(value) > 120 {
		return value[:120]
	}
	return value
}
