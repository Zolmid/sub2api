package cloudflarebridge

import (
	"context"
	"time"
)

// disabledTOTPControlPlane keeps unrelated bridge tests explicit about the
// feature state while satisfying the production fail-closed dependency.
type disabledTOTPControlPlane struct{}

func (disabledTOTPControlPlane) GetTOTPStatus(context.Context, int64) (*CloudflareTOTPStatus, error) {
	return &CloudflareTOTPStatus{Enabled: false}, nil
}

func (disabledTOTPControlPlane) BeginTOTPSetup(context.Context, int64) (*CloudflareTOTPSetup, error) {
	return nil, ErrNotMigrated
}

func (disabledTOTPControlPlane) CompleteTOTPSetup(context.Context, int64, string, string) error {
	return ErrNotMigrated
}

func (disabledTOTPControlPlane) DisableTOTP(context.Context, int64) error {
	return ErrNotMigrated
}

func (disabledTOTPControlPlane) BeginTOTPLogin(context.Context, int64) (*CloudflareTOTPLoginChallenge, error) {
	return nil, ErrNotMigrated
}

func (disabledTOTPControlPlane) VerifyTOTPLogin(context.Context, string, string) (int64, error) {
	return 0, ErrNotMigrated
}

func (disabledTOTPControlPlane) VerifyTOTPStepUp(context.Context, int64, string, string) (time.Duration, error) {
	return 0, ErrNotMigrated
}

func (disabledTOTPControlPlane) HasTOTPStepUp(context.Context, int64, string) (bool, error) {
	return false, ErrNotMigrated
}

func (disabledTOTPControlPlane) RevokeTOTPTransient(context.Context, int64) error {
	return nil
}
