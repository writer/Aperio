package googleworkspaceoauthsync

import "strings"

// googleToken mirrors the subset of Google Directory API
// users.tokens.list payload the sync consumes. Intentionally narrow.
type googleToken struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Scopes      []string `json:"scopes"`
	UserKey     string   `json:"userKey"`
	Anonymous   bool     `json:"anonymous"`
	NativeApp   bool     `json:"nativeApp"`
}

type googleTokensResponse struct {
	Items []googleToken `json:"items"`
}

// parsedToken is the SQL-ready projection of a googleToken.
type parsedToken struct {
	ClientID  string
	Label     string
	Scopes    []string
	Anonymous bool
	NativeApp bool
}

func parseToken(t googleToken) parsedToken {
	return parsedToken{
		ClientID:  strings.TrimSpace(t.ClientID),
		Label:     strings.TrimSpace(t.DisplayText),
		Scopes:    append([]string(nil), t.Scopes...),
		Anonymous: t.Anonymous,
		NativeApp: t.NativeApp,
	}
}

// DisplayName returns the human-readable label that goes into both
// security_assets.name and oauth_app_grants.app_display_name. Falls back
// to the client id when Google did not return a friendly label.
func (p parsedToken) DisplayName() string {
	if p.Label != "" {
		return p.Label
	}
	return p.ClientID
}

// Summary renders a short, deterministic blurb for security_assets.summary
// that the Shadow IT page can show without an extra query. Lists the first
// few scopes to give the reader a quick sense of what the app can do.
func (p parsedToken) Summary() string {
	if len(p.Scopes) == 0 {
		return "Third-party OAuth app"
	}
	preview := p.Scopes
	if len(preview) > 3 {
		preview = preview[:3]
	}
	suffix := ""
	if len(p.Scopes) > 3 {
		suffix = ", +" + itoa(len(p.Scopes)-3) + " more"
	}
	return "OAuth scopes: " + strings.Join(preview, ", ") + suffix
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = digits[n%10]
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
