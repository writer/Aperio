package bootstrap

import (
	"crypto/rand"
	"strconv"
	"time"
)

// This file ports apps/api/src/remediation/executor.ts. The provider handlers
// are simulated exactly as in the original build (canned effects and pseudo
// request identifiers); only Okta and Slack actions report success, while the
// remaining provider actions are explicitly not implemented.

type remediationResult struct {
	Success           bool
	ProviderRequestID string
	Message           string
	Effects           []string
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

func executeRemediation(provider, action, externalAccountID, targetIdentifier string) remediationResult {
	switch action {
	case "okta.suspend_user":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("okta"),
			Message:           "User " + targetIdentifier + " suspended on " + externalAccountID,
			Effects: []string{
				"POST /api/v1/users/" + targetIdentifier + "/lifecycle/suspend",
				"Active sessions invalidated",
				"Sign-in blocked across Okta tenant",
			},
		}
	case "okta.reset_mfa_factors":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("okta"),
			Message:           "MFA factors reset for " + targetIdentifier,
			Effects: []string{
				"POST /api/v1/users/" + targetIdentifier + "/lifecycle/reset_factors",
				"User must re-enroll factors on next sign-in",
			},
		}
	case "slack.deactivate_user":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("slack"),
			Message:           "Slack user " + targetIdentifier + " deactivated",
			Effects: []string{
				"admin.users.session.invalidate",
				"admin.users.remove",
				"DMs preserved, channels left automatically",
			},
		}
	case "slack.revoke_app_install":
		return remediationResult{
			Success:           true,
			ProviderRequestID: pseudoRequestID("slack"),
			Message:           "Slack app " + targetIdentifier + " uninstalled",
			Effects: []string{
				"admin.apps.uninstall",
				"OAuth tokens revoked",
				"Bot user removed from all channels",
			},
		}
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
			Message:           "Action " + action + " for " + provider + " is not yet implemented in this build",
			Effects:           []string{},
		}
	default:
		return remediationResult{
			Success:           false,
			ProviderRequestID: pseudoRequestID("unknown"),
			Message:           "Unknown remediation action " + action,
			Effects:           []string{},
		}
	}
}
