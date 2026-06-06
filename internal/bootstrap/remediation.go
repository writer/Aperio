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
	for _, candidate := range connector.RemediationActions {
		if candidate.Key == action {
			return true
		}
	}
	return false
}

func (a *App) executeRemediation(ctx context.Context, request remediationRequest) remediationResult {
	switch request.Action {
	case "okta.suspend_user":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("okta"),
			Message:           "User " + request.TargetIdentifier + " suspended on " + request.ExternalAccountID,
			Effects: []string{
				"POST /api/v1/users/" + request.TargetIdentifier + "/lifecycle/suspend",
				"Active sessions invalidated",
				"Sign-in blocked across Okta tenant",
			},
		}
	case "okta.reset_mfa_factors":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("okta"),
			Message:           "MFA factors reset for " + request.TargetIdentifier,
			Effects: []string{
				"POST /api/v1/users/" + request.TargetIdentifier + "/lifecycle/reset_factors",
				"User must re-enroll factors on next sign-in",
			},
		}
	case "slack.deactivate_user":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("slack"),
			Message:           "Slack user " + request.TargetIdentifier + " deactivated",
			Effects: []string{
				"admin.users.session.invalidate",
				"admin.users.remove",
				"DMs preserved, channels left automatically",
			},
		}
	case "slack.revoke_app_install":
		return a.executeSlackRevokeAppInstall(ctx, request)
	case "github.revoke_oauth_app",
		"github.enforce_branch_protection",
		"google.suspend_user",
		"google.revoke_oauth_grants",
		"ms365.revoke_sessions",
		"ms365.disable_user",
		"atlassian.revoke_user_access":
		return remediationResult{
			Success:           false,
			ProviderRequestID: pseudoRequestID("noop"),
			Message:           "Action " + request.Action + " for " + request.Provider + " is not yet implemented in this build",
			Effects:           []string{},
		}
	default:
		return remediationResult{
			Success:           false,
			ProviderRequestID: pseudoRequestID("unknown"),
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
			ProviderRequestID: pseudoRequestID("slack"),
			Message:           "Slack app id is required for slack.revoke_app_install",
			Effects:           []string{},
		}
	}
	token := strings.TrimSpace(request.IntegrationToken)
	if token == "" {
		return remediationResult{
			Success:           false,
			ProviderRequestID: pseudoRequestID("slack"),
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
			ProviderRequestID: pseudoRequestID("slack"),
			Message:           "Slack API endpoint is misconfigured",
			Effects:           []string{},
		}
	}

	form := url.Values{"app_id": {target}}
	if workspace := strings.TrimSpace(request.ExternalAccountID); workspace != "" {
		form.Set("team_id", workspace)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return remediationResult{
			Success:           false,
			ProviderRequestID: pseudoRequestID("slack"),
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
			ProviderRequestID: pseudoRequestID("slack"),
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
