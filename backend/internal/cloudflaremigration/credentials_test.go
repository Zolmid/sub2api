package cloudflaremigration

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerCredentialAndLegacyTOTPInteroperability(t *testing.T) {
	targetKey := bytes.Repeat([]byte{0x31}, 32)
	legacyKey := bytes.Repeat([]byte{0x42}, 32)
	hosts, err := ParseAllowedUpstreamHosts("api.openai.com,*.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	transformer := CredentialTransformer{
		TargetKey: targetKey, LegacyTOTPKey: legacyKey, AllowedUpstreamHosts: hosts,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x07}, 24)),
	}
	plaintextAPIKey := "sk-synthetic-never-log"
	credentials, _ := json.Marshal(map[string]any{"api_key": plaintextAPIKey})
	envelope, err := transformer.encryptAccountCredentials("7", "openai", credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(envelope, credentialEnvelopePrefix) || strings.Contains(envelope, plaintextAPIKey) {
		t.Fatal("account credential envelope is malformed or leaked plaintext")
	}
	cleartext := decryptTargetEnvelope(t, envelope, targetKey, nil, credentialEnvelopePrefix)
	if string(cleartext) != "{\"api_key\":\"sk-synthetic-never-log\",\"base_url\":\"https://api.openai.com\"}" {
		t.Fatalf("unexpected Worker credential plaintext shape: %s", cleartext)
	}

	secret := "ABCDEFGHIJKLMNOPQRSTUVWX234567AB"
	legacyEnvelope := encryptLegacyTOTP(t, secret, legacyKey)
	totpEnvelope, err := transformer.reencryptTOTP("9", legacyEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(totpEnvelope, totpEnvelopePrefix) || strings.Contains(totpEnvelope, secret) {
		t.Fatal("TOTP envelope is malformed or leaked plaintext")
	}
	if got := decryptTargetEnvelope(t, totpEnvelope, targetKey, []byte(totpEnvelopeAAD), totpEnvelopePrefix); string(got) != secret {
		t.Fatal("TOTP re-encryption does not match Worker AAD contract")
	}
}

func TestCredentialInputsFailClosedWithoutLeakage(t *testing.T) {
	targetEncoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if key, err := DecodeTargetCredentialKey(targetEncoded); err != nil || len(key) != 32 {
		t.Fatal("valid target key rejected")
	}
	legacyEncoded := hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if key, err := DecodeLegacyTOTPKey(legacyEncoded); err != nil || len(key) != 32 {
		t.Fatal("valid legacy key rejected")
	}
	secret := "do-not-echo-this-secret"
	raw, _ := json.Marshal(map[string]any{"api_key": secret, "refresh_token": secret})
	_, err := (CredentialTransformer{TargetKey: bytes.Repeat([]byte{1}, 32), AllowedUpstreamHosts: []string{"api.openai.com"}}).encryptAccountCredentials("1", "openai", raw)
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "unsupported legacy credential field") {
		t.Fatalf("unsupported credentials did not fail closed safely: %v", err)
	}
}

func encryptLegacyTOTP(t *testing.T, plaintext string, key []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x03}, gcm.NonceSize())
	combined := gcm.Seal(append([]byte(nil), nonce...), nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(combined)
}

func decryptTargetEnvelope(t *testing.T, envelope string, key, aad []byte, prefix string) []byte {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(envelope, prefix), ":")
	if len(parts) != 2 {
		t.Fatal("bad envelope parts")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}
