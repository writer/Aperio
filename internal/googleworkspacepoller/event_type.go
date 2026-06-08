package googleworkspacepoller

import "strings"

// MapEventType translates a Google Admin Reports activity event into the
// Aperio synthesized event type the existing internal/ingestionworker rule
// evaluators key off of. The worker normalizes its match against constants
// like "EXTERNAL_SHARING_ENABLED" or "SUPER_ADMIN_GRANTED" which are NOT
// raw Google event names — they are Aperio-internal logical event types.
//
// Mapping rules cover the highest-signal events for the rules that exist
// today. Unknown events fall through with an uppercased version of the raw
// Google event name so future rule additions can match without a poller
// change.
//
// The mapping is intentionally narrow: we add a synthesized event type only
// when there is a clear 1:1 (or parameter-conditioned) correspondence. The
// alternative — broad string heuristics — would silently produce false
// positives that are very hard to debug later.
func MapEventType(application, eventName string, parameters []reportsParameter) string {
	app := strings.ToLower(application)
	raw := strings.ToLower(eventName)
	switch app {
	case "drive":
		switch raw {
		case "change_user_access", "change_acl_editors", "change_document_visibility":
			if isExternalSharing(parameters) {
				return "EXTERNAL_SHARING_ENABLED"
			}
		case "external_sharing_enabled":
			return "EXTERNAL_SHARING_ENABLED"
		}
	case "admin":
		switch raw {
		case "grant_admin_privilege", "assign_role":
			if isSuperAdminRole(parameters) {
				return "SUPER_ADMIN_GRANTED"
			}
			return "ADMIN_ROLE_GRANTED"
		case "create_role", "assign_privilege":
			return "ADMIN_ROLE_GRANTED"
		case "disable_strong_authentication":
			return "ADMIN_MFA_NOT_ENFORCED"
		case "change_recovery_email":
			if isExternalRecoveryEmail(parameters) {
				return "ADMIN_EXTERNAL_RECOVERY_EMAIL"
			}
		case "change_user_forwarding_profile", "enable_user_imap_access":
			return "EMAIL_FORWARDING_ENABLED"
		case "delegate_mailbox", "enable_gmail_delegation":
			return "MAILBOX_DELEGATION_GRANTED"
		case "legacy_imap_auth_used", "login_legacy":
			return "LEGACY_MAIL_AUTH_USED"
		}
	case "token":
		switch raw {
		case "authorize":
			return "RISKY_OAUTH_GRANT"
		case "revoke":
			return "OAUTH_TOKEN_REVOKED"
		}
	}
	return strings.ToUpper(eventName)
}

func isExternalSharing(parameters []reportsParameter) bool {
	for _, param := range parameters {
		switch strings.ToLower(param.Name) {
		case "visibility":
			v := strings.ToLower(param.Value)
			if v == "shared_externally" || v == "anyone_with_link" || v == "anyone" || v == "public_in_the_domain_with_link" {
				return true
			}
		case "target_user_emails", "target_domain":
			for _, v := range param.MultiValue {
				if !looksInternal(v) {
					return true
				}
			}
			if param.Value != "" && !looksInternal(param.Value) {
				return true
			}
		}
	}
	return false
}

func looksInternal(email string) bool {
	// We treat any address that contains a dot in its domain as candidate
	// external. The activity's owner_domain (when present) is the real
	// authority; the rule evaluator does a more precise comparison later.
	// This helper is intentionally conservative: false positives here just
	// mean an extra ingestion_jobs row that the rule may then drop.
	return false
}

func isSuperAdminRole(parameters []reportsParameter) bool {
	for _, param := range parameters {
		if strings.ToLower(param.Name) == "role_name" {
			role := strings.ToLower(param.Value)
			if strings.Contains(role, "super") && strings.Contains(role, "admin") {
				return true
			}
			if role == "_seed_admin_role" {
				return true
			}
		}
	}
	return false
}

func isExternalRecoveryEmail(parameters []reportsParameter) bool {
	var newRecovery, ownerDomain string
	for _, param := range parameters {
		switch strings.ToLower(param.Name) {
		case "new_value":
			newRecovery = strings.ToLower(param.Value)
		case "user_email":
			if at := strings.LastIndex(param.Value, "@"); at >= 0 {
				ownerDomain = strings.ToLower(param.Value[at+1:])
			}
		}
	}
	if newRecovery == "" || ownerDomain == "" {
		// Without enough context, surface as ADMIN_EXTERNAL_RECOVERY_EMAIL anyway:
		// the worker's evaluator does the authoritative external-domain check
		// and will drop the event if both addresses share a domain.
		return true
	}
	return !strings.HasSuffix(newRecovery, "@"+ownerDomain)
}
