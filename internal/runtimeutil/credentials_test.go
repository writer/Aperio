package runtimeutil

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

type runtimePrimitiveFixture struct {
	Key               string `json:"key"`
	Nonce             string `json:"nonce"`
	AAD               string `json:"aad"`
	WrongAAD          string `json:"wrongAad"`
	Plaintext         string `json:"plaintext"`
	Envelope          string `json:"envelope"`
	MalformedEnvelope string `json:"malformedEnvelope"`
	DatabaseURL       string `json:"databaseUrl"`
}

func TestCredentialEnvelopeCompatibilityAndAADHelpers(t *testing.T) {
	fixture := readRuntimePrimitiveFixture(t)
	t.Setenv("APERIO_ENCRYPTION_KEY", fixture.Key)

	plaintext, err := DecryptString(fixture.Envelope, fixture.AAD)
	if err != nil {
		t.Fatalf("decrypt fixture envelope: %v", err)
	}
	if plaintext != fixture.Plaintext {
		t.Fatalf("plaintext = %q, want %q", plaintext, fixture.Plaintext)
	}

	encrypted, err := EncryptStringWithNonce(fixture.Plaintext, fixture.AAD, []byte(fixture.Nonce))
	if err != nil {
		t.Fatalf("encrypt fixture envelope: %v", err)
	}
	if encrypted != fixture.Envelope {
		t.Fatalf("deterministic envelope mismatch\nwant %s\n got %s", fixture.Envelope, encrypted)
	}

	organizationID := "org_demo"
	integrationID := "int_demo"
	provider := "GITHUB"
	externalAccountID := "writer"
	canonical, err := EncryptStringWithNonce("canonical-token", IntegrationSecretAAD(organizationID, provider, externalAccountID, "access_token"), []byte(fixture.Nonce))
	if err != nil {
		t.Fatalf("encrypt canonical secret: %v", err)
	}
	got, err := DecryptIntegrationSecret(canonical, organizationID, integrationID, provider, externalAccountID, "access_token")
	if err != nil {
		t.Fatalf("decrypt canonical secret: %v", err)
	}
	if got != "canonical-token" {
		t.Fatalf("canonical plaintext = %q", got)
	}

	legacy, err := EncryptStringWithNonce("legacy-token", LegacyIntegrationSecretAAD(organizationID, integrationID, "access_token"), []byte(fixture.Nonce))
	if err != nil {
		t.Fatalf("encrypt legacy secret: %v", err)
	}
	got, err = DecryptIntegrationSecret(legacy, organizationID, integrationID, provider, externalAccountID, "access_token")
	if err != nil {
		t.Fatalf("decrypt legacy secret: %v", err)
	}
	if got != "legacy-token" {
		t.Fatalf("legacy plaintext = %q", got)
	}

	if aad := SIEMDestinationTokenAAD("org_demo", "dst_demo"); aad != "org_demo:siem:dst_demo:token" {
		t.Fatalf("SIEM token AAD = %q", aad)
	}
}

func TestCredentialEnvelopeFailuresAreSafeAndSpecific(t *testing.T) {
	fixture := readRuntimePrimitiveFixture(t)

	t.Run("missing key", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", "")
		_, err := DecryptString(fixture.Envelope, fixture.AAD)
		assertSafeCredentialError(t, err, ErrMissingEncryptionKey, fixture.Plaintext)
	})

	t.Run("malformed envelope", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", fixture.Key)
		_, err := DecryptString(fixture.MalformedEnvelope, fixture.AAD)
		assertSafeCredentialError(t, err, ErrMalformedCredential, fixture.Plaintext)
	})

	t.Run("wrong aad", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", fixture.Key)
		_, err := DecryptString(fixture.Envelope, fixture.WrongAAD)
		assertSafeCredentialError(t, err, ErrCredentialAuthentication, fixture.Plaintext)
	})

	t.Run("tampered tag", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", fixture.Key)
		_, err := DecryptString(tamperEnvelopeTag(t, fixture.Envelope), fixture.AAD)
		assertSafeCredentialError(t, err, ErrCredentialAuthentication, fixture.Plaintext)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", fixture.Key)
		raw, err := base64.RawURLEncoding.DecodeString(fixture.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		var envelope EncryptedEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Algorithm = "aes-128-gcm"
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecryptString(base64.RawURLEncoding.EncodeToString(encoded), fixture.AAD)
		assertSafeCredentialError(t, err, ErrUnsupportedCredential, fixture.Plaintext)
	})

	t.Run("production requires explicit key encoding", func(t *testing.T) {
		_, err := ResolveEncryptionKey("local-passphrase", true)
		assertSafeCredentialError(t, err, ErrProductionEncoding, "local-passphrase")
	})
}

func TestPGXSafeDatabaseURLAndRedaction(t *testing.T) {
	fixture := readRuntimePrimitiveFixture(t)
	safeURL, err := PGXSafeDatabaseURL(fixture.DatabaseURL)
	if err != nil {
		t.Fatalf("pgx-safe URL: %v", err)
	}
	parsed, err := url.Parse(safeURL)
	if err != nil {
		t.Fatalf("parse safe URL: %v", err)
	}
	query := parsed.Query()
	if query.Has("schema") || query.Has("connection_limit") || query.Has("pgbouncer") {
		t.Fatalf("Prisma-only params were not removed: %s", safeURL)
	}
	if query.Get("sslmode") != "disable" {
		t.Fatalf("sslmode = %q, want disable", query.Get("sslmode"))
	}
	if query.Get("application_name") != "aperio" {
		t.Fatalf("application_name not preserved: %s", safeURL)
	}

	secretDSN := (&url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword("aperio", fixture.Plaintext),
		Host:   "127.0.0.1:5433",
		Path:   "/aperio",
	}).String()
	redacted := RedactDSN(secretDSN)
	if strings.Contains(redacted, fixture.Plaintext) || strings.Contains(redacted, "aperio:") {
		t.Fatalf("redacted DSN leaked credentials: %s", redacted)
	}
	if !strings.Contains(redacted, "REDACTED") {
		t.Fatalf("redacted DSN missing redaction marker: %s", redacted)
	}

	message := RedactText("failed with token "+fixture.Plaintext, fixture.Plaintext)
	if strings.Contains(message, fixture.Plaintext) || !strings.Contains(message, Redacted) {
		t.Fatalf("redacted message leaked plaintext: %s", message)
	}
}

func TestLoadEnvFileParsesLocalDotenvWithoutOverwritingByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := strings.Join([]string{
		"# local fixture",
		"APERIO_TEST_RUNTIME_ALPHA=one",
		`APERIO_TEST_RUNTIME_QUOTED="two words"`,
		"export APERIO_TEST_RUNTIME_SINGLE='three#literal'",
		"APERIO_TEST_RUNTIME_COMMENT=four # ignored",
		"APERIO_TEST_RUNTIME_EXISTING=from-file",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APERIO_TEST_RUNTIME_EXISTING", "from-env")

	loaded, err := LoadEnvFile(path, false)
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	if !loaded {
		t.Fatal("expected env file to load")
	}
	assertEnv(t, "APERIO_TEST_RUNTIME_ALPHA", "one")
	assertEnv(t, "APERIO_TEST_RUNTIME_QUOTED", "two words")
	assertEnv(t, "APERIO_TEST_RUNTIME_SINGLE", "three#literal")
	assertEnv(t, "APERIO_TEST_RUNTIME_COMMENT", "four")
	assertEnv(t, "APERIO_TEST_RUNTIME_EXISTING", "from-env")

	if _, err := LoadEnvFile(filepath.Join(dir, "missing.env"), false); err != nil {
		t.Fatalf("missing env file should be a no-op: %v", err)
	}
}

func TestParseEnvValuePreservesEscapedBackslashBeforeControlEscape(t *testing.T) {
	got, err := parseEnvValue(`"literal\\nnot-newline"`)
	if err != nil {
		t.Fatalf("parse env value: %v", err)
	}
	if got != `literal\nnot-newline` {
		t.Fatalf("parseEnvValue preserved escaped backslash = %q, want literal backslash+n", got)
	}
}

func FuzzParseEnvValueDoubleQuotedRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain",
		"two words",
		"line\nbreak",
		"tab\tseparated",
		`literal\nnot-newline`,
		`quote"and\backslash`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			t.Skip()
		}
		got, err := parseEnvValue(quoteDoubleEnvValue(input))
		if err != nil {
			t.Fatalf("parse quoted env value: %v", err)
		}
		if got != input {
			t.Fatalf("double-quoted env round trip mismatch: got %q want %q", got, input)
		}
	})
}

func quoteDoubleEnvValue(input string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range input {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func readRuntimePrimitiveFixture(t *testing.T) runtimePrimitiveFixture {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "runtime-primitives.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture runtimePrimitiveFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertSafeCredentialError(t *testing.T, err error, expected error, plaintext string) {
	t.Helper()
	if !errors.Is(err, expected) {
		t.Fatalf("error = %v, want %v", err, expected)
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatalf("error leaked plaintext %q: %v", plaintext, err)
	}
}

func assertEnv(t *testing.T, key string, want string) {
	t.Helper()
	if got := os.Getenv(key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}

func tamperEnvelopeTag(t *testing.T, encrypted string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var envelope EncryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Tag = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}
