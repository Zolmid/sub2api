package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ManagedBalanceHistoryEntry is the non-secret D1 ledger projection needed by
// the administrator balance-history view. Ledger and operation identifiers are
// intentionally absent from this public-facing projection.
type ManagedBalanceHistoryEntry struct {
	ID                 int64
	AdjustmentType     string
	Reason             string
	DeltaE8USD         string
	BalanceBeforeE8USD string
	BalanceAfterE8USD  string
	CreatedAt          time.Time
}

type ManagedBalanceHistoryPage struct {
	Entries             []ManagedBalanceHistoryEntry
	Total               int64
	TotalRechargedE8USD string
}

type AdminBalanceHistoryControlPlane interface {
	GetManagedBalanceHistory(context.Context, int64, int, int, string) (*ManagedBalanceHistoryPage, error)
}

func signedDisplayBalanceFromE8USD(value string) (float64, error) {
	negative := false
	digits := value
	if strings.HasPrefix(value, "-") {
		negative = true
		digits = value[1:]
	}
	if !canonicalUnsignedDecimal(digits) || len(digits) > 40 || negative && digits == "0" {
		return 0, errors.New("invalid balance history amount")
	}
	amount, err := displayBalanceFromE8USD(digits)
	if err != nil {
		return 0, errors.New("invalid balance history amount")
	}
	if negative {
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
			ID                 string `json:"id"`
			AdjustmentType     string `json:"adjustment_type"`
			Reason             string `json:"reason"`
			DeltaE8USD         string `json:"delta_e8_usd"`
			BalanceBeforeE8USD string `json:"balance_before_e8_usd"`
			BalanceAfterE8USD  string `json:"balance_after_e8_usd"`
			CreatedAt          string `json:"created_at"`
		} `json:"items"`
		Total               string `json:"total"`
		TotalRechargedE8USD string `json:"total_recharged_e8_usd"`
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
	if err != nil || total < 0 || len(response.Items) > pageSize ||
		!canonicalUnsignedDecimal(response.TotalRechargedE8USD) || len(response.TotalRechargedE8USD) > 40 {
		return nil, errors.New("invalid managed balance history response")
	}
	entries := make([]ManagedBalanceHistoryEntry, 0, len(response.Items))
	for _, item := range response.Items {
		entryID, err := parsePositiveID("balance history id", item.ID)
		createdAt, timeErr := requiredWireTime("balance history timestamp", item.CreatedAt)
		_, deltaErr := signedDisplayBalanceFromE8USD(item.DeltaE8USD)
		_, beforeErr := displayBalanceFromE8USD(item.BalanceBeforeE8USD)
		_, afterErr := displayBalanceFromE8USD(item.BalanceAfterE8USD)
		if err != nil || timeErr != nil || deltaErr != nil || beforeErr != nil || afterErr != nil ||
			(item.AdjustmentType != "add" && item.AdjustmentType != "subtract" && item.AdjustmentType != "set") ||
			utf16Length(item.Reason) > 4096 {
			return nil, fmt.Errorf("invalid managed balance history response")
		}
		entries = append(entries, ManagedBalanceHistoryEntry{
			ID: entryID, AdjustmentType: item.AdjustmentType, Reason: item.Reason,
			DeltaE8USD: item.DeltaE8USD, BalanceBeforeE8USD: item.BalanceBeforeE8USD,
			BalanceAfterE8USD: item.BalanceAfterE8USD, CreatedAt: createdAt,
		})
	}
	return &ManagedBalanceHistoryPage{Entries: entries, Total: total, TotalRechargedE8USD: response.TotalRechargedE8USD}, nil
}
