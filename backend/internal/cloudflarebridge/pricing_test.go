package cloudflarebridge

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

func testAdmittedCard() AdmittedPriceCard {
	return AdmittedPriceCard{
		VersionID: "2026-09-09.test", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MaxReservationE8USD: "1000000",
		Rule: E8PricingRule{
			VersionID: "2026-09-09.test", ModelPattern: "fixture-model", MatchKind: "exact",
			InputE8PerMillion: "125000000", OutputE8PerMillion: "1000000000", CacheReadE8PerMillion: "25000000", CacheWriteE8PerMillion: "125000000",
			CacheWrite5mE8PerMillion: "250000000", CacheWrite1hE8PerMillion: "500000000", ImageInputE8PerMillion: "0", ImageOutputE8PerMillion: "0",
			PriorityInputE8PerMillion: "250000000", PriorityOutputE8PerMillion: "2000000000", PriorityCacheReadE8PerMillion: "50000000", PriorityCacheWriteE8PerMillion: "250000000",
			FastMultiplierBPS: "12500", FlexMultiplierBPS: "8000", MaxReasoningEffortMultiplierBPS: "30000",
		},
	}
}

func TestCalculateAdmittedE8ChargeRoundsHalfAwayAtTheE8Boundary(t *testing.T) {
	got, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{InputTokens: 10, OutputTokens: 5, RateMultiplierBPS: "12500"})
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalE8USD != "7813" {
		t.Fatalf("total = %s, want 7813", got.TotalE8USD)
	}
}

func TestCalculateAdmittedE8ChargeIncludesCacheTierAndReasoning(t *testing.T) {
	got, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{
		InputTokens: 1_000_000, ImageInputTokens: 100_000, OutputTokens: 1_000_000, ImageOutputTokens: 100_000,
		CacheCreationTokens: 1_000_000, CacheCreation5mTokens: 250_000, CacheCreation1hTokens: 750_000, CacheReadTokens: 1_000_000,
		ServiceTier: "priority", ReasoningEffort: "max", RateMultiplierBPS: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A configured fast multiplier takes precedence over priority component
	// prices; max reasoning then applies to every component.
	if got.TotalE8USD != "5953125000" {
		t.Fatalf("total = %s, want 5953125000", got.TotalE8USD)
	}
	if !got.ExceedsReservationCap {
		t.Fatal("expected reservation cap indication")
	}
	sum := big.NewInt(0)
	for _, value := range []string{got.InputE8USD, got.ImageInputE8USD, got.OutputE8USD, got.ImageOutputE8USD, got.CacheWriteE8USD, got.CacheReadE8USD} {
		part, ok := new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatalf("invalid component %q", value)
		}
		sum.Add(sum, part)
	}
	if sum.String() != got.TotalE8USD {
		t.Fatalf("components sum to %s, total is %s", sum, got.TotalE8USD)
	}
}

func TestCalculateAdmittedE8ChargeRejectsMalformedCardsAndUsage(t *testing.T) {
	card := testAdmittedCard()
	card.Digest = "not-a-digest"
	if _, err := CalculateAdmittedE8Charge(card, E8Usage{}); err == nil {
		t.Fatal("expected malformed card error")
	}
	if _, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{InputTokens: -1}); err == nil {
		t.Fatal("expected negative usage error")
	}
	card = testAdmittedCard()
	card.Rule.InputE8PerMillion = strings.Repeat("9", 41)
	if err := ValidateAdmittedPriceCard(card); err == nil {
		t.Fatal("expected oversized price error")
	}
	if _, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{RateMultiplierBPS: strings.Repeat("9", 9)}); err == nil {
		t.Fatal("expected oversized rate multiplier error")
	}
}

func TestCalculateAdmittedE8ChargeKeepsCacheWriteAndReadSeparate(t *testing.T) {
	card := testAdmittedCard()
	card.Rule.CacheWrite5mE8PerMillion = "0"
	card.Rule.CacheWrite1hE8PerMillion = "0"
	got, err := CalculateAdmittedE8Charge(card, E8Usage{CacheCreationTokens: 1_000_000, CacheReadTokens: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if got.CacheWriteE8USD != "125000000" || got.CacheReadE8USD != "25000000" || got.TotalE8USD != "150000000" {
		t.Fatalf("unexpected base cache breakdown: %+v", got)
	}
}

func TestCalculateAdmittedE8ChargeMatchesServiceTierPrecedence(t *testing.T) {
	card := testAdmittedCard()
	fast, err := CalculateAdmittedE8Charge(card, E8Usage{InputTokens: 1_000_000, ServiceTier: "fast"})
	if err != nil {
		t.Fatal(err)
	}
	if fast.InputE8USD != "156250000" {
		t.Fatalf("configured fast multiplier did not override priority prices: %s", fast.InputE8USD)
	}
	card.Rule.FastMultiplierBPS = "0"
	priority, err := CalculateAdmittedE8Charge(card, E8Usage{InputTokens: 1_000_000, ServiceTier: "priority"})
	if err != nil {
		t.Fatal(err)
	}
	if priority.InputE8USD != "250000000" {
		t.Fatalf("priority input = %s", priority.InputE8USD)
	}
	card.Rule.FlexMultiplierBPS = "0"
	flex, err := CalculateAdmittedE8Charge(card, E8Usage{InputTokens: 1_000_000, ServiceTier: "flex"})
	if err != nil {
		t.Fatal(err)
	}
	if flex.InputE8USD != "62500000" {
		t.Fatalf("default flex input = %s", flex.InputE8USD)
	}
}

func TestValidateAdmittedPriceCardMatchesNormalizedModel(t *testing.T) {
	card := testAdmittedCard()
	card.Rule.MatchKind = "family"
	card.Rule.ModelPattern = "claude-fable-5-1*"
	if err := ValidateAdmittedPriceCardForModel(card, "  Claude-Fable-5.1-20260909 "); err != nil {
		t.Fatalf("normalized family match failed: %v", err)
	}
	if err := ValidateAdmittedPriceCardForModel(card, "gpt-5.6"); err == nil {
		t.Fatal("expected family mismatch")
	}
	card.Rule.MatchKind = "exact"
	if err := ValidateAdmittedPriceCard(card); err == nil {
		t.Fatal("expected exact rule with wildcard to fail")
	}
}

func TestCalculateAdmittedE8ChargeNormalizesContradictoryCacheDetails(t *testing.T) {
	got, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{
		CacheCreationTokens:   100,
		CacheCreation5mTokens: 90,
		CacheCreation1hTokens: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Traditional billing rounds 100*90/150 to 60/100 5m tokens and assigns
	// the remainder to 1h: 60*250 + 40*500 e8 per million.
	if got.CacheWriteE8USD != "35000" || got.TotalE8USD != "35000" {
		t.Fatalf("normalized cache charge = %+v", got)
	}
}

func TestCalculateAdmittedE8ChargeRejectsDetailWithoutCacheCreationTotal(t *testing.T) {
	_, err := CalculateAdmittedE8Charge(testAdmittedCard(), E8Usage{CacheCreation5mTokens: 1})
	if !errors.Is(err, ErrInvalidE8Usage) {
		t.Fatalf("error = %v, want ErrInvalidE8Usage", err)
	}
}
