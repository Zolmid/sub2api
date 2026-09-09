package cloudflarebridge

import (
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

type AdmittedPriceCard struct {
	VersionID           string        `json:"version_id"`
	Digest              string        `json:"digest"`
	MaxReservationE8USD string        `json:"max_reservation_e8_usd"`
	Rule                E8PricingRule `json:"rule"`
}

type E8PricingRule struct {
	VersionID                       string `json:"version_id"`
	ModelPattern                    string `json:"model_pattern"`
	MatchKind                       string `json:"match_kind"`
	InputE8PerMillion               string `json:"input_e8_per_million"`
	OutputE8PerMillion              string `json:"output_e8_per_million"`
	CacheReadE8PerMillion           string `json:"cache_read_e8_per_million"`
	CacheWriteE8PerMillion          string `json:"cache_write_e8_per_million"`
	CacheWrite5mE8PerMillion        string `json:"cache_write_5m_e8_per_million"`
	CacheWrite1hE8PerMillion        string `json:"cache_write_1h_e8_per_million"`
	ImageInputE8PerMillion          string `json:"image_input_e8_per_million"`
	ImageOutputE8PerMillion         string `json:"image_output_e8_per_million"`
	PriorityInputE8PerMillion       string `json:"priority_input_e8_per_million"`
	PriorityOutputE8PerMillion      string `json:"priority_output_e8_per_million"`
	PriorityCacheReadE8PerMillion   string `json:"priority_cache_read_e8_per_million"`
	PriorityCacheWriteE8PerMillion  string `json:"priority_cache_write_e8_per_million"`
	FastMultiplierBPS               string `json:"fast_multiplier_bps"`
	FlexMultiplierBPS               string `json:"flex_multiplier_bps"`
	MaxReasoningEffortMultiplierBPS string `json:"max_reasoning_effort_multiplier_bps"`
}

type E8Usage struct {
	InputTokens           int64
	ImageInputTokens      int64
	OutputTokens          int64
	ImageOutputTokens     int64
	CacheCreationTokens   int64
	CacheCreation5mTokens int64
	CacheCreation1hTokens int64
	CacheReadTokens       int64
	ServiceTier           string
	ReasoningEffort       string
	RateMultiplierBPS     string
}

type E8ChargeBreakdown struct {
	InputE8USD            string
	ImageInputE8USD       string
	OutputE8USD           string
	ImageOutputE8USD      string
	CacheWriteE8USD       string
	CacheReadE8USD        string
	TotalE8USD            string
	VersionID             string
	Digest                string
	ReservationCapE8USD   string
	ExceedsReservationCap bool
}

var (
	ErrInvalidAdmittedPriceCard = errors.New("invalid admitted price card")
	ErrInvalidE8Usage           = errors.New("invalid e8 usage")
	unsignedE8                  = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	positiveE8                  = regexp.MustCompile(`^[1-9][0-9]*$`)
	digestE8                    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionIDE8                 = regexp.MustCompile(`^[a-z0-9._:-]{1,128}$`)
	pricingModelE8              = regexp.MustCompile(`^[a-z0-9._:/-]+$`)
	priceDenominator            = big.NewInt(1_000_000)
	bpsDenominator              = big.NewInt(10_000)
)

func parseE8(value string, positive bool) (*big.Int, error) {
	if len(value) < 1 || len(value) > 40 ||
		(positive && !positiveE8.MatchString(value)) || (!positive && !unsignedE8.MatchString(value)) {
		return nil, ErrInvalidAdmittedPriceCard
	}
	v, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, ErrInvalidAdmittedPriceCard
	}
	return v, nil
}

func parseBPS(value string, positive bool) (*big.Int, error) {
	if len(value) > 8 {
		return nil, ErrInvalidAdmittedPriceCard
	}
	return parseE8(value, positive)
}

func normalizePricingModel(value string) (string, bool) {
	if len(value) < 1 || len(value) > 256 {
		return "", false
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || !pricingModelE8.MatchString(normalized) {
		return "", false
	}
	if strings.HasPrefix(normalized, "claude-") {
		normalized = strings.ReplaceAll(normalized, ".", "-")
	}
	return normalized, true
}

func ValidateAdmittedPriceCard(card AdmittedPriceCard) error {
	if !versionIDE8.MatchString(card.VersionID) || !digestE8.MatchString(card.Digest) ||
		card.Rule.VersionID != card.VersionID || card.Rule.MatchKind != "exact" && card.Rule.MatchKind != "family" {
		return ErrInvalidAdmittedPriceCard
	}
	if _, err := parseE8(card.MaxReservationE8USD, true); err != nil {
		return err
	}
	pattern := card.Rule.ModelPattern
	if len(pattern) < 1 || len(pattern) > 257 {
		return ErrInvalidAdmittedPriceCard
	}
	if card.Rule.MatchKind == "family" {
		if !strings.HasSuffix(pattern, "*") || strings.Contains(pattern[:len(pattern)-1], "*") {
			return ErrInvalidAdmittedPriceCard
		}
		base, ok := normalizePricingModel(pattern[:len(pattern)-1])
		if !ok || base+"*" != pattern {
			return ErrInvalidAdmittedPriceCard
		}
	} else {
		base, ok := normalizePricingModel(pattern)
		if !ok || base != pattern || strings.Contains(pattern, "*") {
			return ErrInvalidAdmittedPriceCard
		}
	}
	for _, value := range []string{card.Rule.InputE8PerMillion, card.Rule.OutputE8PerMillion, card.Rule.CacheReadE8PerMillion, card.Rule.CacheWriteE8PerMillion, card.Rule.CacheWrite5mE8PerMillion, card.Rule.CacheWrite1hE8PerMillion, card.Rule.ImageInputE8PerMillion, card.Rule.ImageOutputE8PerMillion, card.Rule.PriorityInputE8PerMillion, card.Rule.PriorityOutputE8PerMillion, card.Rule.PriorityCacheReadE8PerMillion, card.Rule.PriorityCacheWriteE8PerMillion, card.Rule.FastMultiplierBPS, card.Rule.FlexMultiplierBPS} {
		if _, err := parseE8(value, false); err != nil {
			return err
		}
	}
	if _, err := parseBPS(card.Rule.FastMultiplierBPS, false); err != nil {
		return err
	}
	if _, err := parseBPS(card.Rule.FlexMultiplierBPS, false); err != nil {
		return err
	}
	_, err := parseBPS(card.Rule.MaxReasoningEffortMultiplierBPS, true)
	return err
}

func ValidateAdmittedPriceCardForModel(card AdmittedPriceCard, model string) error {
	if err := ValidateAdmittedPriceCard(card); err != nil {
		return err
	}
	normalized, ok := normalizePricingModel(model)
	if !ok {
		return ErrInvalidAdmittedPriceCard
	}
	if card.Rule.MatchKind == "exact" && card.Rule.ModelPattern != normalized {
		return ErrInvalidAdmittedPriceCard
	}
	if card.Rule.MatchKind == "family" && !strings.HasPrefix(normalized, strings.TrimSuffix(card.Rule.ModelPattern, "*")) {
		return ErrInvalidAdmittedPriceCard
	}
	return nil
}

type exactPart struct {
	numerator   *big.Int
	denominator *big.Int
	index       int
}

func tokenPart(tokens int64, price *big.Int, index int) (exactPart, error) {
	if tokens < 0 {
		return exactPart{}, ErrInvalidE8Usage
	}
	return exactPart{numerator: new(big.Int).Mul(big.NewInt(tokens), price), denominator: new(big.Int).Set(priceDenominator), index: index}, nil
}

func multiply(part exactPart, bps *big.Int) exactPart {
	part.numerator.Mul(part.numerator, bps)
	part.denominator.Mul(part.denominator, bpsDenominator)
	return part
}

func normalizeCacheCreation(tokens E8Usage) (int64, int64, error) {
	if tokens.CacheCreationTokens < 0 || tokens.CacheCreation5mTokens < 0 || tokens.CacheCreation1hTokens < 0 {
		return 0, 0, ErrInvalidE8Usage
	}
	if tokens.CacheCreationTokens <= 0 || (tokens.CacheCreation5mTokens <= tokens.CacheCreationTokens && tokens.CacheCreation1hTokens <= tokens.CacheCreationTokens-tokens.CacheCreation5mTokens) {
		return tokens.CacheCreation5mTokens, tokens.CacheCreation1hTokens, nil
	}
	detail := new(big.Int).Add(big.NewInt(tokens.CacheCreation5mTokens), big.NewInt(tokens.CacheCreation1hTokens))
	if detail.Sign() <= 0 {
		return 0, 0, ErrInvalidE8Usage
	}
	// Traditional code uses math.Round for this ratio; for positive integer
	// tokens this is the same deterministic half-up allocation.
	n := new(big.Int).Mul(big.NewInt(tokens.CacheCreationTokens), big.NewInt(tokens.CacheCreation5mTokens))
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(n, detail, r)
	if new(big.Int).Lsh(r, 1).Cmp(detail) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	if q.Int64() >= tokens.CacheCreationTokens {
		return tokens.CacheCreationTokens, 0, nil
	}
	return q.Int64(), tokens.CacheCreationTokens - q.Int64(), nil
}

func nonzero(value *big.Int, fallback *big.Int) *big.Int {
	if value.Sign() > 0 {
		return value
	}
	return fallback
}

func allocate(parts []exactPart) ([]*big.Int, *big.Int, error) {
	if len(parts) == 0 || parts[0].denominator.Sign() <= 0 {
		return nil, nil, ErrInvalidE8Usage
	}
	den := new(big.Int).Set(parts[0].denominator)
	totalNumerator := big.NewInt(0)
	for _, part := range parts {
		if part.denominator.Cmp(den) != 0 || part.numerator.Sign() < 0 {
			return nil, nil, ErrInvalidE8Usage
		}
		totalNumerator.Add(totalNumerator, part.numerator)
	}
	total, remainder := new(big.Int), new(big.Int)
	total.QuoRem(totalNumerator, den, remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(den) >= 0 {
		total.Add(total, big.NewInt(1))
	}
	values, remainders := make([]*big.Int, len(parts)), make([]*big.Int, len(parts))
	sum := big.NewInt(0)
	for i, part := range parts {
		values[i], remainders[i] = new(big.Int), new(big.Int)
		values[i].QuoRem(part.numerator, den, remainders[i])
		sum.Add(sum, values[i])
	}
	order := make([]int, len(parts))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		c := remainders[order[i]].Cmp(remainders[order[j]])
		return c > 0 || (c == 0 && parts[order[i]].index < parts[order[j]].index)
	})
	delta := new(big.Int).Sub(total, sum)
	if !delta.IsInt64() || delta.Sign() < 0 || delta.Cmp(big.NewInt(int64(len(parts)))) > 0 {
		return nil, nil, ErrInvalidE8Usage
	}
	for i := int64(0); i < delta.Int64(); i++ {
		values[order[i]].Add(values[order[i]], big.NewInt(1))
	}
	return values, total, nil
}

func CalculateAdmittedE8Charge(card AdmittedPriceCard, usage E8Usage) (*E8ChargeBreakdown, error) {
	if err := ValidateAdmittedPriceCard(card); err != nil {
		return nil, err
	}
	for _, value := range []int64{usage.InputTokens, usage.ImageInputTokens, usage.OutputTokens, usage.ImageOutputTokens, usage.CacheReadTokens} {
		if value < 0 {
			return nil, ErrInvalidE8Usage
		}
	}
	p := func(value string) *big.Int { n, _ := parseE8(value, false); return n }
	input, output, read, write := p(card.Rule.InputE8PerMillion), p(card.Rule.OutputE8PerMillion), p(card.Rule.CacheReadE8PerMillion), p(card.Rule.CacheWriteE8PerMillion)
	tier := strings.ToLower(strings.TrimSpace(usage.ServiceTier))
	multiplier := big.NewInt(10_000)
	if tier == "fast" || tier == "priority" {
		fast := p(card.Rule.FastMultiplierBPS)
		if fast.Sign() > 0 {
			multiplier = fast
		} else if p(card.Rule.PriorityInputE8PerMillion).Sign() > 0 || p(card.Rule.PriorityOutputE8PerMillion).Sign() > 0 || p(card.Rule.PriorityCacheReadE8PerMillion).Sign() > 0 || p(card.Rule.PriorityCacheWriteE8PerMillion).Sign() > 0 {
			input, output, read, write = nonzero(p(card.Rule.PriorityInputE8PerMillion), input), nonzero(p(card.Rule.PriorityOutputE8PerMillion), output), nonzero(p(card.Rule.PriorityCacheReadE8PerMillion), read), nonzero(p(card.Rule.PriorityCacheWriteE8PerMillion), write)
		} else {
			multiplier = big.NewInt(20_000)
		}
	} else if tier == "flex" {
		if configured := p(card.Rule.FlexMultiplierBPS); configured.Sign() > 0 {
			multiplier = configured
		} else {
			multiplier = big.NewInt(5_000)
		}
	}
	imageIn := usage.ImageInputTokens
	if imageIn > usage.InputTokens {
		imageIn = usage.InputTokens
	}
	imageOut := usage.ImageOutputTokens
	if imageOut > usage.OutputTokens {
		imageOut = usage.OutputTokens
	}
	parts := make([]exactPart, 0, 7)
	appendPart := func(tokens int64, price *big.Int) error {
		part, err := tokenPart(tokens, price, len(parts))
		if err == nil {
			parts = append(parts, multiply(part, multiplier))
		}
		return err
	}
	if err := appendPart(usage.InputTokens-imageIn, input); err != nil {
		return nil, err
	}
	if err := appendPart(imageIn, nonzero(p(card.Rule.ImageInputE8PerMillion), input)); err != nil {
		return nil, err
	}
	if err := appendPart(usage.OutputTokens-imageOut, output); err != nil {
		return nil, err
	}
	if err := appendPart(imageOut, nonzero(p(card.Rule.ImageOutputE8PerMillion), output)); err != nil {
		return nil, err
	}
	five, hour, err := normalizeCacheCreation(usage)
	if err != nil {
		return nil, err
	}
	fivePrice, hourPrice := p(card.Rule.CacheWrite5mE8PerMillion), p(card.Rule.CacheWrite1hE8PerMillion)
	if fivePrice.Sign() > 0 || hourPrice.Sign() > 0 {
		if five == 0 && hour == 0 && usage.CacheCreationTokens > 0 {
			five = usage.CacheCreationTokens
		}
		if err := appendPart(five, fivePrice); err != nil {
			return nil, err
		}
		if err := appendPart(hour, hourPrice); err != nil {
			return nil, err
		}
	} else {
		if err := appendPart(usage.CacheCreationTokens, write); err != nil {
			return nil, err
		}
		if err := appendPart(0, write); err != nil {
			return nil, err
		}
	}
	if err := appendPart(usage.CacheReadTokens, read); err != nil {
		return nil, err
	}
	rate := usage.RateMultiplierBPS
	if rate == "" {
		rate = "10000"
	}
	rateBPS, err := parseBPS(rate, true)
	if err != nil {
		return nil, ErrInvalidE8Usage
	}
	for i := range parts {
		parts[i] = multiply(parts[i], rateBPS)
		if strings.EqualFold(strings.TrimSpace(usage.ReasoningEffort), "max") {
			max, _ := parseE8(card.Rule.MaxReasoningEffortMultiplierBPS, true)
			parts[i] = multiply(parts[i], max)
		}
	}
	values, total, err := allocate(parts)
	if err != nil {
		return nil, err
	}
	cap, _ := parseE8(card.MaxReservationE8USD, true)
	return &E8ChargeBreakdown{InputE8USD: values[0].String(), ImageInputE8USD: values[1].String(), OutputE8USD: values[2].String(), ImageOutputE8USD: values[3].String(), CacheWriteE8USD: new(big.Int).Add(values[4], values[5]).String(), CacheReadE8USD: values[len(values)-1].String(), TotalE8USD: total.String(), VersionID: card.VersionID, Digest: card.Digest, ReservationCapE8USD: cap.String(), ExceedsReservationCap: total.Cmp(cap) > 0}, nil
}
