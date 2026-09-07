package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ManagedBalanceHistoryEntry is the non-secret D1 ledger projection needed by
// the administrator balance-history view. Ledger and operation identifiers are
// intentionally absent from this public-facing projection.
type ManagedBalanceHistoryEntry struct {
	ID                    int64
	AdjustmentType        string
	Reason                string
	DeltaMicroUSD         string
	BalanceBeforeMicroUSD string
	BalanceAfterMicroUSD  string
	CreatedAt             time.Time
}

type ManagedBalanceHistoryPage struct {
	Entries        []ManagedBalanceHistoryEntry
	Total          int64
	TotalRecharged float64
}

type AdminBalanceHistoryControlPlane interface {
	GetManagedBalanceHistory(context.Context, int64, int, int, string) (*ManagedBalanceHistoryPage, error)
}

func signedDisplayBalanceFromMicroUSD(value string) (float64, error) {
	negative := false
	digits := value
	if strings.HasPrefix(value, "-") {
		negative = true
		digits = value[1:]
	}
	if !canonicalUnsignedDecimal(digits) || len(digits) > 40 {
		return 0, errors.New("invalid balance history amount")
	}
	microUSD, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || microUSD > maxExactFloatInteger {
		return 0, errors.New("balance history amount is not exactly representable")
	}
	amount := float64(microUSD) / float64(microUSDPerUSD)
	if math.IsNaN(amount) || math.IsInf(amount, 0) || uint64(math.Round(amount*float64(microUSDPerUSD))) != microUSD {
		return 0, errors.New("balance history amount is not exactly representable")
	}
	if negative && microUSD != 0 {
		return -amount, nil
	}
	return amount, nil
}

func (c *HTTPControlPlane) GetManagedBalanceHistory(ctx context.Context, userID int64, page, pageSize int, codeType string) (*ManagedBalanceHistoryPage, error) {
	if userID < 1 || page < 1 || pageSize < 1 || pageSize > 100 {
		return nil, service.ErrUserNotFound
	}
	var response struct {
		Items []struct {
			ID                    string `json:"id"`
			AdjustmentType        string `json:"adjustment_type"`
			Reason                string `json:"reason"`
			DeltaMicroUSD         string `json:"delta_microusd"`
			BalanceBeforeMicroUSD string `json:"balance_before_microusd"`
			BalanceAfterMicroUSD  string `json:"balance_after_microusd"`
			CreatedAt             string `json:"created_at"`
		} `json:"items"`
		Total          string  `json:"total"`
		TotalRecharged float64 `json:"total_recharged"`
	}
	request := struct {
		ID       string `json:"id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
		Type     string `json:"type,omitempty"`
	}{
		ID: strconv.FormatInt(userID, 10), Page: page, PageSize: pageSize, Type: codeType,
	}
	if err := c.post(ctx, "/v1/manage/users/balance-history", request, &response); err != nil {
		return nil, mapManagedReadError(err, service.ErrUserNotFound)
	}
	total, err := strconv.ParseInt(response.Total, 10, 64)
	if err != nil || total < 0 || len(response.Items) > pageSize || math.IsNaN(response.TotalRecharged) || math.IsInf(response.TotalRecharged, 0) {
		return nil, errors.New("invalid managed balance history response")
	}
	entries := make([]ManagedBalanceHistoryEntry, 0, len(response.Items))
	for _, item := range response.Items {
		entryID, err := parsePositiveID("balance history id", item.ID)
		createdAt, timeErr := requiredWireTime("balance history timestamp", item.CreatedAt)
		_, deltaErr := signedDisplayBalanceFromMicroUSD(item.DeltaMicroUSD)
		_, beforeErr := displayBalanceFromMicroUSD(item.BalanceBeforeMicroUSD)
		_, afterErr := displayBalanceFromMicroUSD(item.BalanceAfterMicroUSD)
		if err != nil || timeErr != nil || deltaErr != nil || beforeErr != nil || afterErr != nil ||
			(item.AdjustmentType != "add" && item.AdjustmentType != "subtract" && item.AdjustmentType != "set") ||
			len(item.Reason) > 4096 {
			return nil, fmt.Errorf("invalid managed balance history response")
		}
		entries = append(entries, ManagedBalanceHistoryEntry{
			ID: entryID, AdjustmentType: item.AdjustmentType, Reason: item.Reason,
			DeltaMicroUSD: item.DeltaMicroUSD, BalanceBeforeMicroUSD: item.BalanceBeforeMicroUSD,
			BalanceAfterMicroUSD: item.BalanceAfterMicroUSD, CreatedAt: createdAt,
		})
	}
	return &ManagedBalanceHistoryPage{Entries: entries, Total: total, TotalRecharged: response.TotalRecharged}, nil
}
