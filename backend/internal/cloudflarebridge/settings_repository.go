package cloudflarebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	settingsRequestIDPrefix = "settings-v1:"
	settingsMaxValueBytes   = 16_384
	settingsMaxVersion      = int64(9_223_372_036_854_775_807)
)

var (
	settingsKeyPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	settingsVersionPattern   = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	settingsRequestIDPattern = regexp.MustCompile(`^settings-v1:[A-Za-z0-9_-]{43}$`)
)

// SettingsRepository adapts the legacy SettingRepository contract to the
// private Worker settings control plane. It deliberately exposes no CAS state:
// the legacy interface has only unconditional upsert/delete operations.
type SettingsRepository struct {
	control   *HTTPControlPlane
	requestID func() (string, error)
}

var _ service.SettingRepository = (*SettingsRepository)(nil)

func NewSettingsRepository(control *HTTPControlPlane) *SettingsRepository {
	return &SettingsRepository{control: control, requestID: newSettingsRequestID}
}

func newSettingsRequestID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate settings request id: %w", err)
	}
	return settingsRequestIDPrefix + base64.RawURLEncoding.EncodeToString(bytes), nil
}

type settingReadResponse struct {
	Key       string  `json:"key"`
	Value     *string `json:"value"`
	Version   string  `json:"version"`
	UpdatedAt string  `json:"updatedAt"`
}

type settingWriteResponse struct {
	Key      string `json:"key"`
	Version  string `json:"version"`
	Deleted  *bool  `json:"deleted"`
	Replayed *bool  `json:"replayed"`
}

// strictSettingsMap rejects non-string values and duplicate keys instead of
// letting encoding/json silently overwrite a prior value. Map keys are the
// setting keys themselves, so there is no fixed schema of field names to
// whitelist here.
type strictSettingsMap map[string]string

func (m *strictSettingsMap) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("settings response must be an object")
	}
	values := make(map[string]string)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || !validSettingsKey(key) {
			return errors.New("settings response has an invalid key")
		}
		if _, exists := values[key]; exists {
			return errors.New("settings response has a duplicate key")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if !validSettingsValue(value) {
			return errors.New("settings response has an invalid value")
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil {
		return err
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errors.New("settings response must be an object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("settings response has trailing JSON")
	}
	*m = values
	return nil
}

func (r *SettingsRepository) Get(ctx context.Context, key string) (*service.Setting, error) {
	var response *settingReadResponse
	if err := r.post(ctx, "/v1/private/settings/get", struct {
		Key string `json:"key"`
	}{Key: key}, &response); err != nil {
		return nil, mapSettingsReadError(err)
	}
	if response == nil {
		return nil, service.ErrSettingNotFound
	}
	return decodeSettingRead(key, response)
}

func (r *SettingsRepository) GetValue(ctx context.Context, key string) (string, error) {
	var response *string
	if err := r.post(ctx, "/v1/private/settings/get-value", struct {
		Key string `json:"key"`
	}{Key: key}, &response); err != nil {
		return "", mapSettingsReadError(err)
	}
	if response == nil || !validSettingsValue(*response) {
		return "", errors.New("invalid settings get-value response")
	}
	return *response, nil
}

func (r *SettingsRepository) Set(ctx context.Context, key, value string) error {
	requestID, err := r.nextRequestID()
	if err != nil {
		return err
	}
	var response settingWriteResponse
	if err := r.postMutation(ctx, "/v1/private/settings/set", struct {
		Key       string `json:"key"`
		Value     string `json:"value"`
		RequestID string `json:"request_id"`
	}{Key: key, Value: value, RequestID: requestID}, &response); err != nil {
		return err
	}
	return validateSettingWrite(key, false, response)
}

func (r *SettingsRepository) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	var response strictSettingsMap
	if err := r.post(ctx, "/v1/private/settings/get-multiple", struct {
		Keys []string `json:"keys"`
	}{Keys: keys}, &response); err != nil {
		return nil, err
	}
	requested := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		requested[key] = struct{}{}
	}
	for key := range response {
		if _, ok := requested[key]; !ok {
			return nil, errors.New("invalid settings get-multiple response: unrequested key")
		}
	}
	return map[string]string(response), nil
}

func (r *SettingsRepository) SetMultiple(ctx context.Context, settings map[string]string) error {
	if len(settings) == 0 {
		return nil
	}
	requestID, err := r.nextRequestID()
	if err != nil {
		return err
	}
	var response []settingWriteResponse
	if err := r.postMutation(ctx, "/v1/private/settings/set-multiple", struct {
		Values    map[string]string `json:"values"`
		RequestID string            `json:"request_id"`
	}{Values: settings, RequestID: requestID}, &response); err != nil {
		return err
	}
	if len(response) != len(settings) {
		return errors.New("invalid settings set-multiple response: result count")
	}
	seen := make(map[string]struct{}, len(response))
	for _, result := range response {
		if _, exists := settings[result.Key]; !exists {
			return errors.New("invalid settings set-multiple response: unexpected key")
		}
		if _, duplicate := seen[result.Key]; duplicate {
			return errors.New("invalid settings set-multiple response: duplicate key")
		}
		seen[result.Key] = struct{}{}
		if err := validateSettingWrite(result.Key, false, result); err != nil {
			return fmt.Errorf("invalid settings set-multiple response: %w", err)
		}
	}
	return nil
}

func (r *SettingsRepository) GetAll(ctx context.Context) (map[string]string, error) {
	var response strictSettingsMap
	if err := r.post(ctx, "/v1/private/settings/get-all", struct{}{}, &response); err != nil {
		return nil, err
	}
	return map[string]string(response), nil
}

func (r *SettingsRepository) Delete(ctx context.Context, key string) error {
	requestID, err := r.nextRequestID()
	if err != nil {
		return err
	}
	var response settingWriteResponse
	if err := r.postMutation(ctx, "/v1/private/settings/delete", struct {
		Key       string `json:"key"`
		RequestID string `json:"request_id"`
	}{Key: key, RequestID: requestID}, &response); err != nil {
		return mapSettingsReadError(err)
	}
	return validateSettingWrite(key, true, response)
}

func (r *SettingsRepository) post(ctx context.Context, path string, input, output any) error {
	if r == nil || r.control == nil {
		return ErrNotMigrated
	}
	return r.control.post(ctx, path, input, output)
}

func (r *SettingsRepository) postMutation(ctx context.Context, path string, input, output any) error {
	if r == nil || r.control == nil {
		return ErrNotMigrated
	}
	return r.control.postManagedMutation(ctx, path, input, output)
}

func (r *SettingsRepository) nextRequestID() (string, error) {
	if r == nil || r.requestID == nil {
		return "", errors.New("settings request id source is unavailable")
	}
	requestID, err := r.requestID()
	if err != nil {
		return "", err
	}
	if !settingsRequestIDPattern.MatchString(requestID) {
		return "", errors.New("settings request id source returned a non-canonical id")
	}
	return requestID, nil
}

func mapSettingsReadError(err error) error {
	var responseErr *controlPlaneResponseError
	if errors.As(err, &responseErr) && responseErr.Code == "NOT_FOUND" {
		return service.ErrSettingNotFound
	}
	return err
}

func decodeSettingRead(expectedKey string, response *settingReadResponse) (*service.Setting, error) {
	if response == nil || response.Key != expectedKey || !validSettingsKey(response.Key) ||
		response.Value == nil || !validSettingsValue(*response.Value) || !validSettingsVersion(response.Version) {
		return nil, errors.New("invalid settings get response")
	}
	updatedAt, err := parseSettingsTimestamp(response.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid settings get response: %w", err)
	}
	return &service.Setting{Key: response.Key, Value: *response.Value, UpdatedAt: updatedAt}, nil
}

func validateSettingWrite(expectedKey string, deleted bool, response settingWriteResponse) error {
	if response.Key != expectedKey || !validSettingsKey(response.Key) || !validSettingsVersion(response.Version) ||
		response.Deleted == nil || *response.Deleted != deleted || response.Replayed == nil {
		return errors.New("invalid settings write response")
	}
	return nil
}

func validSettingsKey(value string) bool {
	return settingsKeyPattern.MatchString(value)
}

func validSettingsValue(value string) bool {
	return len(value) <= settingsMaxValueBytes && !strings.ContainsRune(value, '\x00')
}

func validSettingsVersion(value string) bool {
	if !settingsVersionPattern.MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && parsed > 0 && parsed <= settingsMaxVersion
}

func parseSettingsTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || parsed.UTC().Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}
