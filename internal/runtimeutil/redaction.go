package runtimeutil

import (
	"net/url"
	"strings"
)

const Redacted = "[REDACTED]"

func RedactSecret(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return Redacted
}

func RedactText(input string, secrets ...string) string {
	output := input
	for _, secret := range secrets {
		trimmed := strings.TrimSpace(secret)
		if len(trimmed) < 4 {
			continue
		}
		output = strings.ReplaceAll(output, trimmed, Redacted)
	}
	return output
}

func RedactError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	return RedactText(err.Error(), secrets...)
}

func RedactDSN(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return RedactText(trimmed)
	}
	if parsed.User != nil {
		if _, ok := parsed.User.Password(); ok {
			parsed.User = url.UserPassword(Redacted, Redacted)
		} else if parsed.User.Username() != "" {
			parsed.User = url.User(Redacted)
		}
	}
	query := parsed.Query()
	for key, values := range query {
		if !isSensitiveKey(key) {
			continue
		}
		for index := range values {
			values[index] = Redacted
		}
		query[key] = values
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "api-key") ||
		normalized == "key" ||
		strings.Contains(normalized, "credential")
}
