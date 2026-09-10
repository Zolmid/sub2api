//go:build unit

package cloudflarebridge

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type billingGolden struct {
	Scale          int    `json:"scale"`
	MaxPublicE8USD string `json:"max_public_e8_usd"`
	DecimalVectors []struct {
		Input             string `json:"input"`
		CanonicalUnsigned bool   `json:"canonical_unsigned"`
		CanonicalPositive bool   `json:"canonical_positive"`
		WithinPublicMax   bool   `json:"within_public_max"`
	} `json:"decimal_vectors"`
	StartRPC        json.RawMessage `json:"start_rpc"`
	CompletionRPC   json.RawMessage `json:"completion_rpc"`
	BillingIdentity json.RawMessage `json:"billing_identity"`
}

func loadBillingGolden(t *testing.T) billingGolden {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate billing golden test source")
	}
	if !filepath.IsAbs(sourceFile) {
		var err error
		sourceFile, err = filepath.Abs(sourceFile)
		if err != nil {
			t.Fatalf("resolve billing golden test source: %v", err)
		}
	}
	path := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "testdata", "billing_e8_golden.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared billing golden: %v", err)
	}
	var golden billingGolden
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&golden); err != nil {
		t.Fatalf("decode shared billing golden: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("shared billing golden has trailing JSON: %v", err)
	}
	return golden
}

func decodeGoldenRPC[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()
	var value T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode golden RPC: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("golden RPC has trailing JSON: %v", err)
	}
	return value
}

func TestSharedBillingGoldenE8Vectors(t *testing.T) {
	golden := loadBillingGolden(t)
	if golden.Scale != 8 {
		t.Fatalf("scale = %d, want 8", golden.Scale)
	}
	maximum, ok := new(big.Int).SetString(golden.MaxPublicE8USD, 10)
	if !ok {
		t.Fatalf("invalid public maximum %q", golden.MaxPublicE8USD)
	}
	for _, vector := range golden.DecimalVectors {
		value, err := parseE8(vector.Input, false)
		if (err == nil) != vector.CanonicalUnsigned {
			t.Fatalf("parseE8(%q) error = %v, canonical_unsigned = %v", vector.Input, err, vector.CanonicalUnsigned)
		}
		positive := isCanonicalPositiveDecimal(vector.Input)
		if positive != vector.CanonicalPositive {
			t.Fatalf("positive(%q) = %v, want %v", vector.Input, positive, vector.CanonicalPositive)
		}
		within := err == nil && value.Cmp(maximum) <= 0
		if within != vector.WithinPublicMax {
			t.Fatalf("within max(%q) = %v, want %v", vector.Input, within, vector.WithinPublicMax)
		}
	}
}

func TestSharedBillingGoldenRPCVectors(t *testing.T) {
	golden := loadBillingGolden(t)
	start := decodeGoldenRPC[StartRequest](t, golden.StartRPC)
	if start.RequestID != "golden-request" || start.LeaseEpoch != "7" {
		t.Fatalf("unexpected start vector: %+v", start)
	}
	completion := decodeGoldenRPC[CompletionRequest](t, golden.CompletionRPC)
	if completion.SchemaVersion != UsageSchemaVersion ||
		completion.EventType != UsageEventType ||
		completion.UsageState != UsageConfirmed ||
		completion.InputTokens != "0" ||
		completion.OutputTokens != "0" {
		t.Fatalf("unexpected completion vector: %+v", completion)
	}
	encoded, err := json.Marshal(completion)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual any
	if err := json.Unmarshal(golden.CompletionRPC, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if !deepEqualJSON(expected, actual) {
		t.Fatalf("completion serialization differs\nexpected: %s\nactual:   %s", golden.CompletionRPC, encoded)
	}
}

func deepEqualJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
