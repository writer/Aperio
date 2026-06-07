package bootstrap

type remediationActionClass string

const (
	remediationActionRealProvider remediationActionClass = "real-provider"
	remediationActionLocalOnly    remediationActionClass = "local-only"
	remediationActionUnsupported  remediationActionClass = "unsupported"
)

type remediationActionDefinition struct {
	Provider string
	Action   string
	Class    remediationActionClass
}

var remediationActionDefinitions = []remediationActionDefinition{
	{Provider: "GITHUB", Action: "github.revoke_oauth_app", Class: remediationActionUnsupported},
	{Provider: "GITHUB", Action: "github.enforce_branch_protection", Class: remediationActionUnsupported},
	{Provider: "SLACK", Action: "slack.deactivate_user", Class: remediationActionUnsupported},
	{Provider: "SLACK", Action: "slack.revoke_app_install", Class: remediationActionRealProvider},
	{Provider: "GOOGLE_WORKSPACE", Action: "google.suspend_user", Class: remediationActionUnsupported},
	{Provider: "GOOGLE_WORKSPACE", Action: "google.revoke_oauth_grants", Class: remediationActionUnsupported},
	{Provider: "OKTA", Action: "okta.suspend_user", Class: remediationActionUnsupported},
	{Provider: "OKTA", Action: "okta.reset_mfa_factors", Class: remediationActionUnsupported},
	{Provider: "MICROSOFT_365", Action: "ms365.revoke_sessions", Class: remediationActionUnsupported},
	{Provider: "MICROSOFT_365", Action: "ms365.disable_user", Class: remediationActionUnsupported},
	{Provider: "ATLASSIAN", Action: "atlassian.revoke_user_access", Class: remediationActionUnsupported},
}

func findRemediationActionDefinition(action string) (remediationActionDefinition, bool) {
	for _, definition := range remediationActionDefinitions {
		if definition.Action == action {
			return definition, true
		}
	}
	return remediationActionDefinition{}, false
}

func isExecutableRemediationAction(action string) bool {
	definition, ok := findRemediationActionDefinition(action)
	if !ok {
		return false
	}
	return definition.Class == remediationActionRealProvider || definition.Class == remediationActionLocalOnly
}
