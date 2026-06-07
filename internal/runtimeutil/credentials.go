package runtimeutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	CredentialAlgorithm  = "aes-256-gcm"
	CredentialKeyBytes   = 32
	CredentialNonceBytes = 12
)

var (
	ErrMissingEncryptionKey      = errors.New("APERIO_ENCRYPTION_KEY is required")
	ErrInvalidEncryptionKey      = errors.New("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes")
	ErrProductionEncoding        = errors.New("APERIO_ENCRYPTION_KEY must use base64:, base64url:, or hex: encoding in production")
	ErrEmptyCredentialPlaintext  = errors.New("Cannot encrypt an empty string")
	ErrMalformedCredential       = errors.New("Encrypted value is malformed")
	ErrUnsupportedCredential     = errors.New("Unsupported encrypted value version or algorithm")
	ErrCredentialAuthentication  = errors.New("Encrypted value authentication failed")
	ErrInvalidCredentialNonceLen = errors.New("invalid encryption nonce length")
)

type EncryptedEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	IV         string `json:"iv"`
	Tag        string `json:"tag"`
	Ciphertext string `json:"ciphertext"`
}

func ResolveEncryptionKeyFromEnv() ([]byte, error) {
	return ResolveEncryptionKey(os.Getenv("APERIO_ENCRYPTION_KEY"), os.Getenv("NODE_ENV") == "production")
}

func ResolveEncryptionKey(rawKey string, production bool) ([]byte, error) {
	raw := strings.TrimSpace(rawKey)
	if raw == "" {
		return nil, ErrMissingEncryptionKey
	}
	switch {
	case strings.HasPrefix(raw, "base64:"):
		key, err := decodeBase64(strings.TrimPrefix(raw, "base64:"))
		if err != nil {
			return nil, err
		}
		if len(key) != CredentialKeyBytes {
			return nil, ErrInvalidEncryptionKey
		}
		return key, nil
	case strings.HasPrefix(raw, "base64url:"):
		key, err := decodeBase64URL(strings.TrimPrefix(raw, "base64url:"))
		if err != nil {
			return nil, err
		}
		if len(key) != CredentialKeyBytes {
			return nil, ErrInvalidEncryptionKey
		}
		return key, nil
	case strings.HasPrefix(raw, "hex:"):
		key, err := hex.DecodeString(strings.TrimPrefix(raw, "hex:"))
		if err != nil {
			return nil, err
		}
		if len(key) != CredentialKeyBytes {
			return nil, ErrInvalidEncryptionKey
		}
		return key, nil
	default:
		if production {
			return nil, ErrProductionEncoding
		}
		return scrypt.Key([]byte(raw), []byte("aperio-token-vault"), 16384, 8, 1, CredentialKeyBytes)
	}
}

func EncryptString(plaintext string, additionalAuthenticatedData string) (string, error) {
	nonce := make([]byte, CredentialNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return EncryptStringWithNonce(plaintext, additionalAuthenticatedData, nonce)
}

func EncryptStringWithNonce(plaintext string, additionalAuthenticatedData string, nonce []byte) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyCredentialPlaintext
	}
	if len(nonce) != CredentialNonceBytes {
		return "", ErrInvalidCredentialNonceLen
	}
	key, err := ResolveEncryptionKeyFromEnv()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(additionalAuthenticatedData))
	tagStart := len(sealed) - gcm.Overhead()
	envelope := EncryptedEnvelope{
		Version:    1,
		Algorithm:  CredentialAlgorithm,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Tag:        base64.RawURLEncoding.EncodeToString(sealed[tagStart:]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed[:tagStart]),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func DecryptString(encryptedValue string, additionalAuthenticatedData string) (string, error) {
	raw, err := decodeBase64URL(encryptedValue)
	if err != nil {
		return "", ErrMalformedCredential
	}
	var envelope EncryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", ErrMalformedCredential
	}
	if envelope.Version != 1 || envelope.Algorithm != CredentialAlgorithm {
		return "", ErrUnsupportedCredential
	}
	iv, err := decodeBase64URL(envelope.IV)
	if err != nil {
		return "", ErrMalformedCredential
	}
	tag, err := decodeBase64URL(envelope.Tag)
	if err != nil {
		return "", ErrMalformedCredential
	}
	ciphertext, err := decodeBase64URL(envelope.Ciphertext)
	if err != nil {
		return "", ErrMalformedCredential
	}
	key, err := ResolveEncryptionKeyFromEnv()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(iv) != gcm.NonceSize() {
		return "", ErrMalformedCredential
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(additionalAuthenticatedData))
	if err != nil {
		return "", ErrCredentialAuthentication
	}
	return string(plaintext), nil
}

func IntegrationSecretAAD(organizationID string, provider string, externalAccountID string, suffix string) string {
	return organizationID + ":" + provider + ":" + externalAccountID + ":" + suffix
}

func LegacyIntegrationSecretAAD(organizationID string, integrationID string, suffix string) string {
	return organizationID + ":" + integrationID + ":" + suffix
}

func SIEMDestinationTokenAAD(organizationID string, destinationID string) string {
	return organizationID + ":siem:" + destinationID + ":token"
}

func DecryptIntegrationSecret(encryptedValue string, organizationID string, integrationID string, provider string, externalAccountID string, suffix string) (string, error) {
	canonical, err := DecryptString(encryptedValue, IntegrationSecretAAD(organizationID, provider, externalAccountID, suffix))
	if err == nil {
		return canonical, nil
	}
	if strings.TrimSpace(integrationID) == "" {
		return "", err
	}
	legacy, legacyErr := DecryptString(encryptedValue, LegacyIntegrationSecretAAD(organizationID, integrationID, suffix))
	if legacyErr == nil {
		return legacy, nil
	}
	return "", err
}

func DecryptGoogleMailboxPrivateKey(encryptedValue string, organizationID string, integrationID string, externalAccountID string) (string, error) {
	canonical, err := DecryptString(encryptedValue, IntegrationSecretAAD(organizationID, "GOOGLE_WORKSPACE", externalAccountID, "gmail_scan_private_key"))
	if err == nil {
		return canonical, nil
	}
	if strings.TrimSpace(integrationID) == "" {
		return "", err
	}
	legacy, legacyErr := DecryptString(encryptedValue, LegacyIntegrationSecretAAD(organizationID, integrationID, "google_mailbox_private_key"))
	if legacyErr == nil {
		return legacy, nil
	}
	return "", err
}

func decodeBase64(value string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func decodeBase64URL(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}
