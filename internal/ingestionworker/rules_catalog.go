package ingestionworker

// RuleCatalogEntry is the user-visible metadata for one built-in finding
// rule. The connectors UI surfaces every entry alongside an on/off toggle
// backed by integration_connections.disabled_checks. This catalog is the
// SOLE source of truth for what shows up in the toggle list; adding a new
// rule means: (1) write the evaluator, (2) add it to Evaluate(), (3) add
// it to the corresponding supportedIngestionEventTypes provider, (4) add
// an entry here so it appears in the UI.
type RuleCatalogEntry struct {
	ID          string
	Provider    string
	Title       string
	Description string
	Severity    string
	EventTypes  []string
}

// RuleCatalog is the registered list of built-in rules. Order is the
// display order in the UI.
var RuleCatalog = []RuleCatalogEntry{
	{
		ID:          "github.public_repository_created",
		Provider:    "GITHUB",
		Title:       "Public GitHub repository created",
		Description: "A repository was created or changed to public visibility, which can expose source code, secrets, or customer data.",
		Severity:    "CRITICAL",
		EventTypes:  []string{"PUBLIC_REPOSITORY_CREATED", "REPOSITORY_PUBLICIZED"},
	},
	{
		ID:          "slack.mfa_disabled",
		Provider:    "SLACK",
		Title:       "Slack multi-factor authentication disabled",
		Description: "A Slack user disabled MFA, increasing the likelihood of account takeover and lateral movement.",
		Severity:    "CRITICAL",
		EventTypes:  []string{"MFA_DISABLED", "TWO_FACTOR_AUTH_DISABLED"},
	},
	{
		ID:          "okta.admin_role_assigned",
		Provider:    "OKTA",
		Title:       "Okta admin role assigned",
		Description: "A user was granted an Okta administrator role, expanding their tenant-wide privileges.",
		Severity:    "HIGH",
		EventTypes:  []string{"USER_ACCOUNT_PRIVILEGE_GRANT", "USER_ACCOUNT_PRIVILEGE_GRANTED", "ADMIN_ROLE_ASSIGNED", "ROLE_ASSIGNMENT_CREATED"},
	},
	{
		ID:          "okta.mfa_factor_reset",
		Provider:    "OKTA",
		Title:       "Okta MFA factor reset",
		Description: "A user's MFA factors were reset, which can be abused for account-takeover bypass during phishing.",
		Severity:    "HIGH",
		EventTypes:  []string{"USER_MFA_FACTOR_RESET", "USER_MFA_FACTOR_DEACTIVATE"},
	},
	{
		ID:          "okta.password_policy_weakened",
		Provider:    "OKTA",
		Title:       "Okta password policy weakened",
		Description: "An Okta password policy was changed to relax length, complexity, or rotation requirements.",
		Severity:    "HIGH",
		EventTypes:  []string{"POLICY_RULE_UPDATE", "PASSWORD_POLICY_UPDATE"},
	},
	{
		ID:          "okta.suspicious_signin",
		Provider:    "OKTA",
		Title:       "Okta suspicious sign-in",
		Description: "A sign-in matched Okta's suspicious-activity signal (impossible travel, anomalous device, or threat intel hit).",
		Severity:    "HIGH",
		EventTypes:  []string{"USER_SESSION_START", "SECURITY_THREAT_DETECTED"},
	},
	{
		ID:          "google_workspace.external_sharing_enabled",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Google Drive external sharing enabled",
		Description: "A Drive resource was shared outside the tenant domain or set to a public visibility scope.",
		Severity:    "HIGH",
		EventTypes:  []string{"EXTERNAL_SHARING_ENABLED"},
	},
	{
		ID:          "google_workspace.super_admin_granted",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Google Workspace Super Admin role granted",
		Description: "A user was promoted to Super Admin, granting tenant-wide control over Workspace.",
		Severity:    "CRITICAL",
		EventTypes:  []string{"SUPER_ADMIN_GRANTED"},
	},
	{
		ID:          "google_workspace.admin_role_granted",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Google Workspace admin role granted",
		Description: "A user received a delegated administrator role, expanding their tenant privileges.",
		Severity:    "HIGH",
		EventTypes:  []string{"ADMIN_ROLE_GRANTED"},
	},
	{
		ID:          "google_workspace.risky_oauth_grant",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Risky third-party OAuth grant",
		Description: "A third-party OAuth app was authorized with sensitive scopes that broaden tenant data access.",
		Severity:    "HIGH",
		EventTypes:  []string{"RISKY_OAUTH_GRANT"},
	},
	{
		ID:          "google_workspace.admin_mfa_not_enforced",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Admin MFA enforcement disabled",
		Description: "Strong authentication enforcement was disabled for an admin, weakening the privileged-account perimeter.",
		Severity:    "HIGH",
		EventTypes:  []string{"ADMIN_MFA_NOT_ENFORCED"},
	},
	{
		ID:          "google_workspace.admin_external_recovery_email",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Admin external recovery email set",
		Description: "An admin's recovery email was changed to an external domain, creating an out-of-band account-takeover path.",
		Severity:    "HIGH",
		EventTypes:  []string{"ADMIN_EXTERNAL_RECOVERY_EMAIL"},
	},
	{
		ID:          "google_workspace.email_forwarding_enabled",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Email forwarding enabled",
		Description: "Mail forwarding or IMAP was enabled on a mailbox, opening a data-exfiltration channel.",
		Severity:    "MEDIUM",
		EventTypes:  []string{"EMAIL_FORWARDING_ENABLED"},
	},
	{
		ID:          "google_workspace.mailbox_delegation_granted",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Mailbox delegation granted",
		Description: "Mailbox delegation was granted, letting another account read or send mail on the mailbox owner's behalf.",
		Severity:    "MEDIUM",
		EventTypes:  []string{"MAILBOX_DELEGATION_GRANTED"},
	},
	{
		ID:          "google_workspace.legacy_mail_auth_used",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Legacy mail authentication used",
		Description: "A legacy IMAP/SMTP authentication path was used, which bypasses modern MFA and risk-based sign-in controls.",
		Severity:    "MEDIUM",
		EventTypes:  []string{"LEGACY_MAIL_AUTH_USED"},
	},
	{
		ID:          "google_workspace.forwarding_delegate_send_as_combo",
		Provider:    "GOOGLE_WORKSPACE",
		Title:       "Forwarding + delegation + send-as combo",
		Description: "A mailbox simultaneously has forwarding, delegation, and send-as configured — a classic exfiltration staging pattern.",
		Severity:    "HIGH",
		EventTypes:  []string{"FORWARDING_DELEGATE_SEND_AS_COMBO"},
	},
}

// RuleCatalogForProvider returns the rules registered for a given
// provider, preserving display order. An unknown provider returns nil.
func RuleCatalogForProvider(provider string) []RuleCatalogEntry {
	out := make([]RuleCatalogEntry, 0, 4)
	for _, entry := range RuleCatalog {
		if entry.Provider == provider {
			out = append(out, entry)
		}
	}
	return out
}
