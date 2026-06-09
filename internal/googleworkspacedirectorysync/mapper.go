package googleworkspacedirectorysync

import (
	"strings"
	"time"
)

// dormantWindow matches the dormancy threshold the Security Graph already
// uses (dormantIdentityWindow in internal/bootstrap/security_overview.go).
// Keeping the two in sync prevents the awkward case where the report shows
// a user as "active" while the graph shows them as "dormant".
const dormantWindow = 30 * 24 * time.Hour

// googleUser is the Directory API users.get/list payload subset the sync
// reads. Intentionally narrow: only fields the saas_identities upsert
// consumes are modeled, so future Directory API additions pass through
// untouched.
type googleUser struct {
	ID               string         `json:"id"`
	PrimaryEmail     string         `json:"primaryEmail"`
	Name             googleUserName `json:"name"`
	Suspended        bool           `json:"suspended"`
	Archived         bool           `json:"archived"`
	IsAdmin          bool           `json:"isAdmin"`
	IsDelegatedAdmin bool           `json:"isDelegatedAdmin"`
	IsEnforcedIn2Sv  bool           `json:"isEnforcedIn2Sv"`
	IsEnrolledIn2Sv  bool           `json:"isEnrolledIn2Sv"`
	LastLoginTime    time.Time      `json:"lastLoginTime"`
	CreationTime     time.Time      `json:"creationTime"`
	OrgUnitPath      string         `json:"orgUnitPath"`
	CustomerID       string         `json:"customerId"`
}

type googleUserName struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	FullName   string `json:"fullName"`
}

type googleUsersResponse struct {
	Users         []googleUser `json:"users"`
	NextPageToken string       `json:"nextPageToken,omitempty"`
}

// mappedIdentity is the SQL-ready projection of a googleUser. The fields
// line up 1:1 with the saas_identities columns the upsert writes.
type mappedIdentity struct {
	ExternalID   string
	Email        string
	DisplayName  string
	Status       string // ACTIVE | SUSPENDED | DORMANT
	Role         string
	MfaEnabled   *bool
	IsPrivileged bool
	IsExternal   bool
}

// mapIdentity translates one googleUser into the saas_identities row shape.
// The tenantDomain comparison decides is_external: an identity whose
// primary email is not @tenantDomain is treated as a guest / federated
// user. When tenantDomain is empty we conservatively report is_external
// = false rather than flagging every user as external — a permissive
// default here would falsely promote MFA coverage shortfalls into the
// "external risk" panel of the report.
func mapIdentity(u googleUser, tenantDomain string, now time.Time) mappedIdentity {
	mfa := u.IsEnforcedIn2Sv || u.IsEnrolledIn2Sv
	return mappedIdentity{
		ExternalID:   u.ID,
		Email:        strings.ToLower(strings.TrimSpace(u.PrimaryEmail)),
		DisplayName:  u.Name.FullName,
		Status:       mapStatus(u, now),
		Role:         mapRole(u),
		MfaEnabled:   &mfa,
		IsPrivileged: u.IsAdmin || u.IsDelegatedAdmin,
		IsExternal:   isExternalUser(u.PrimaryEmail, tenantDomain),
	}
}

// mapStatus collapses Google's three orthogonal flags (suspended, archived,
// lastLoginTime) into the Aperio SaasIdentityStatus enum. The precedence
// matters: a suspended/archived user that has never logged in must still
// surface as SUSPENDED, otherwise the dormancy heuristic would mask an
// active suspension.
func mapStatus(u googleUser, now time.Time) string {
	if u.Suspended || u.Archived {
		return "SUSPENDED"
	}
	// A user with no recorded lastLoginTime AND a creationTime older than
	// the dormancy window is reported DORMANT — a brand new account that
	// hasn't logged in yet is still ACTIVE for the dormancy window.
	if u.LastLoginTime.IsZero() {
		if !u.CreationTime.IsZero() && now.Sub(u.CreationTime) > dormantWindow {
			return "DORMANT"
		}
		return "ACTIVE"
	}
	if now.Sub(u.LastLoginTime) > dormantWindow {
		return "DORMANT"
	}
	return "ACTIVE"
}

// mapRole picks a human-readable role label for the report. The
// Google Directory API does not return a free-text role for non-admin
// users, and the explicit "Super Admin" vs "Delegated Admin" distinction
// is the only role signal a report consumer can act on without an
// additional roleAssignments.list call.
func mapRole(u googleUser) string {
	switch {
	case u.IsAdmin:
		return "Super Admin"
	case u.IsDelegatedAdmin:
		return "Delegated Admin"
	default:
		return ""
	}
}

// isExternalUser returns true when the user's email is hosted on a domain
// other than the tenant's verified primary domain. Mirrors the conservative
// "unknown means internal" default that the audit-log poller's
// isExternalEmail uses (internal/googleworkspacepoller/event_type.go).
func isExternalUser(email, tenantDomain string) bool {
	td := strings.TrimSpace(strings.ToLower(tenantDomain))
	em := strings.TrimSpace(strings.ToLower(email))
	if td == "" || em == "" {
		return false
	}
	at := strings.LastIndex(em, "@")
	if at < 0 || at == len(em)-1 {
		return false
	}
	return !strings.EqualFold(em[at+1:], td)
}
