package runtimeutil

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var dotenvKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func LoadLocalEnv(overwrite bool) (bool, error) {
	return LoadEnvFile(".env", overwrite)
}

func LoadEnvFile(path string, overwrite bool) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		index := strings.Index(line, "=")
		if index < 0 {
			return false, fmt.Errorf("invalid env assignment on line %d", lineNumber)
		}
		key := strings.TrimSpace(line[:index])
		if !dotenvKeyPattern.MatchString(key) {
			return false, fmt.Errorf("invalid env key at line %d", lineNumber)
		}
		if _, exists := os.LookupEnv(key); exists && !overwrite {
			continue
		}
		value, err := parseEnvValue(line[index+1:])
		if err != nil {
			return false, fmt.Errorf("invalid env value for %s on line %d", key, lineNumber)
		}
		if err := os.Setenv(key, value); err != nil {
			return false, err
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return true, nil
}

func PGXSafeDatabaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("DATABASE_URL is not a valid URL")
	}
	query := parsed.Query()
	query.Del("schema")
	query.Del("connection_limit")
	query.Del("pgbouncer")
	if query.Get("sslmode") == "" && isLocalDatabaseHost(parsed.Hostname()) {
		query.Set("sslmode", "disable")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func parseEnvValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, `"`) {
		if !strings.HasSuffix(value, `"`) || len(value) == 1 {
			return "", errors.New("unterminated quoted value")
		}
		unquoted := strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
		return unescapeDoubleQuotedEnvValue(unquoted), nil
	}
	if strings.HasPrefix(value, `'`) {
		if !strings.HasSuffix(value, `'`) || len(value) == 1 {
			return "", errors.New("unterminated quoted value")
		}
		return strings.TrimSuffix(strings.TrimPrefix(value, `'`), `'`), nil
	}
	if comment := inlineCommentIndex(value); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	return value, nil
}

func unescapeDoubleQuotedEnvValue(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index == len(value)-1 {
			builder.WriteByte(value[index])
			continue
		}
		index++
		switch value[index] {
		case 'n':
			builder.WriteByte('\n')
		case 'r':
			builder.WriteByte('\r')
		case 't':
			builder.WriteByte('\t')
		case '"':
			builder.WriteByte('"')
		case '\\':
			builder.WriteByte('\\')
		default:
			builder.WriteByte('\\')
			builder.WriteByte(value[index])
		}
	}
	return builder.String()
}

func inlineCommentIndex(value string) int {
	for index := 0; index < len(value); index++ {
		if value[index] == '#' && (index == 0 || value[index-1] == ' ' || value[index-1] == '\t') {
			return index
		}
	}
	return -1
}

func isLocalDatabaseHost(host string) bool {
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	default:
		return false
	}
}
