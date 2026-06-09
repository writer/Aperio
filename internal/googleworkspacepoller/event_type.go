package googleworkspacepoller

import "strings"

// MapEventType translates a Google Admin Reports activity event into the
// Aperio synthesized event type the existing internal/ingestionworker rule
// evaluators key off of. The worker normalizes its match against constants
// like "EXTERNAL_SHARING_ENABLED" or "SUPER_ADMIN_GRANTED" which are NOT
// raw Google event names — they are Aperio-internal logical event types.
//
// ownerDomain is the workspace's own hosted domain (derived by the poller
// from the activity actor, parameters.owner, or the integration's stored
// externalAccountID). The drive sharing classifier needs it to tell internal
// shares apart from external ones; if it is empty the classifier is
// conservative and refuses to fire EXTERNAL_SHARING_ENABLED on target-based
// signals (visibility-based detection still works).
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
func MapEventType(application, eventName string, parameters []reportsParameter, ownerDomain string) string {
	app := strings.ToLower(application)
	raw := strings.ToLower(eventName)
	switch app {
	case "drive":
		switch raw {
		case "change_user_access", "change_acl_editors", "change_document_visibility":
			if isExternalSharing(parameters, ownerDomain) {
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

// isExternalSharing returns true when a Drive change_* activity describes
// sharing with a party outside ownerDomain. Two kinds of signals fire it:
//
//  1. visibility transitions whose target side is inherently public
//     (shared_externally, anyone_with_link, anyone, public_in_the_domain_with_link).
//     These are independent of any target-email comparison; if visibility
//     opens to the public the file is externally shared regardless of who
//     happens to be in target_user_emails.
//
//  2. target_user_emails / target_domain that name a party whose domain
//     is not ownerDomain. Internal-only shares (e.g. target_user_emails =
//     ["alice@company.com"] when ownerDomain == "company.com") must NOT
//     fire this rule — that was the bug the reviewer caught with the
//     dead looksInternal helper. We now compare domains explicitly.
//
// When ownerDomain is empty (the poller could not derive one from the
// actor, parameters, or integration) we deliberately do NOT fire on
// target-based signals. The downstream worker has no internal/external
// gating of its own, so a permissive default here would produce HIGH-
// severity false positives on every routine internal share — the exact
// regression the reviewer flagged.
func isExternalSharing(parameters []reportsParameter, ownerDomain string) bool {
	for _, param := range parameters {
		switch strings.ToLower(param.Name) {
		case "visibility":
			v := strings.ToLower(param.Value)
			if v == "shared_externally" || v == "anyone_with_link" || v == "anyone" || v == "public_in_the_domain_with_link" {
				return true
			}
		case "target_user_emails":
			for _, v := range param.MultiValue {
				if isExternalEmail(v, ownerDomain) {
					return true
				}
			}
			if param.Value != "" && isExternalEmail(param.Value, ownerDomain) {
				return true
			}
		case "target_domain":
			for _, v := range param.MultiValue {
				if isExternalDomain(v, ownerDomain) {
					return true
				}
			}
			if param.Value != "" && isExternalDomain(param.Value, ownerDomain) {
				return true
			}
		}
	}
	return false
}

// isExternalEmail returns true only when ownerDomain is known AND the email
// is clearly hosted on a different domain. The conservative default (false)
// is critical: with an unknown ownerDomain the downstream worker would
// promote every share into a HIGH-severity finding, so silence is safer
// than a false-positive flood.
func isExternalEmail(email, ownerDomain string) bool {
	if strings.TrimSpace(ownerDomain) == "" || strings.TrimSpace(email) == "" {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	return !strings.EqualFold(email[at+1:], ownerDomain)
}

// isExternalDomain mirrors isExternalEmail's conservative-when-unknown
// behavior for the target_domain parameter shape (which carries a bare
// domain, not an addr-spec).
func isExternalDomain(domain, ownerDomain string) bool {
	if strings.TrimSpace(ownerDomain) == "" || strings.TrimSpace(domain) == "" {
		return false
	}
	return !strings.EqualFold(domain, ownerDomain)
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
