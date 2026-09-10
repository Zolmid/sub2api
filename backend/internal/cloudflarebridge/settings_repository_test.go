package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const testSettingsRequestID = "settings-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func newSettingsTestRepository(t *testing.T, handler http.HandlerFunc) *SettingsRepository {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewSettingsRepository(control)
	repository.requestID = func() (string, error) { return testSettingsRequestID, nil }
	return repository
}

func decodeSettingsRequest(t *testing.T, request *http.Request, path string, output any) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != path || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		t.Fatal("request contains trailing JSON")
	}
}

func TestSettingsRepository_Get(t *testing.T) {
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Key string `json:"key"`
		}
		decodeSettingsRequest(t, request, "/v1/private/settings/get", &body)
		if body.Key != "alpha" {
			t.Fatalf("key = %q", body.Key)
		}
		_, _ = writer.Write([]byte(`{"key":"alpha","value":"one","version":"7","updatedAt":"2026-09-10T10:11:12.123Z"}`))
	})

	setting, err := repository.Get(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if setting.Key != "alpha" || setting.Value != "one" || setting.ID != 0 || setting.UpdatedAt.Format("2006-01-02T15:04:05.000Z") != "2026-09-10T10:11:12.123Z" {
		t.Fatalf("unexpected setting: %#v", setting)
	}
}

func TestSettingsRepository_GetMissingAndMalformed(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			decodeSettingsRequest(t, request, "/v1/private/settings/get", &struct {
				Key string `json:"key"`
			}{})
			_, _ = writer.Write([]byte(`null`))
		})
		setting, err := repository.Get(context.Background(), "missing")
		if setting != nil || !errors.Is(err, service.ErrSettingNotFound) {
			t.Fatalf("setting=%v err=%v", setting, err)
		}
	})
	t.Run("unknown response field", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(`{"key":"alpha","value":"one","version":"1","updatedAt":"2026-09-10T10:11:12.123Z","extra":true}`))
		})
		if _, err := repository.Get(context.Background(), "alpha"); err == nil || !errors.Is(err, ErrControlPlaneUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSettingsRepository_GetValue(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			decodeSettingsRequest(t, request, "/v1/private/settings/get-value", &struct {
				Key string `json:"key"`
			}{})
			_, _ = writer.Write([]byte(`"one"`))
		})
		value, err := repository.GetValue(context.Background(), "alpha")
		if err != nil || value != "one" {
			t.Fatalf("value=%q err=%v", value, err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"error":{"code":"SETTING_NOT_FOUND","message":"setting missing"}}`))
		})
		_, err := repository.GetValue(context.Background(), "missing")
		if !errors.Is(err, service.ErrSettingNotFound) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSettingsRepository_Set(t *testing.T) {
	var calls int
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		var body struct {
			Key       string `json:"key"`
			Value     string `json:"value"`
			RequestID string `json:"request_id"`
		}
		decodeSettingsRequest(t, request, "/v1/private/settings/set", &body)
		if body.Key != "alpha" || body.Value != "one" || body.RequestID != testSettingsRequestID {
			t.Fatalf("unexpected body: %#v", body)
		}
		_, _ = writer.Write([]byte(`{"key":"alpha","version":"1","deleted":false,"replayed":false}`))
	})
	if err := repository.Set(context.Background(), "alpha", "one"); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSettingsRepository_GetMultiple(t *testing.T) {
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Keys []string `json:"keys"`
		}
		decodeSettingsRequest(t, request, "/v1/private/settings/get-multiple", &body)
		if strings.Join(body.Keys, ",") != "alpha,missing" {
			t.Fatalf("keys=%v", body.Keys)
		}
		_, _ = writer.Write([]byte(`{"alpha":"one"}`))
	})
	values, err := repository.GetMultiple(context.Background(), []string{"alpha", "missing"})
	if err != nil || len(values) != 1 || values["alpha"] != "one" {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestSettingsRepository_SetMultiple(t *testing.T) {
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Values    map[string]string `json:"values"`
			RequestID string            `json:"request_id"`
		}
		decodeSettingsRequest(t, request, "/v1/private/settings/set-multiple", &body)
		if len(body.Values) != 2 || body.Values["alpha"] != "one" || body.Values["beta"] != "two" || body.RequestID != testSettingsRequestID {
			t.Fatalf("unexpected body: %#v", body)
		}
		_, _ = writer.Write([]byte(`[{"key":"alpha","version":"1","deleted":false,"replayed":false},{"key":"beta","version":"2","deleted":false,"replayed":true}]`))
	})
	if err := repository.SetMultiple(context.Background(), map[string]string{"alpha": "one", "beta": "two"}); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsRepository_GetAll(t *testing.T) {
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		decodeSettingsRequest(t, request, "/v1/private/settings/get-all", &struct{}{})
		_, _ = writer.Write([]byte(`{"alpha":"one","beta":"two"}`))
	})
	values, err := repository.GetAll(context.Background())
	if err != nil || len(values) != 2 || values["beta"] != "two" {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestSettingsRepository_DeleteAndReplaySafeRequestID(t *testing.T) {
	var mu sync.Mutex
	var requestIDs []string
	repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Key       string `json:"key"`
			RequestID string `json:"request_id"`
		}
		decodeSettingsRequest(t, request, "/v1/private/settings/delete", &body)
		mu.Lock()
		requestIDs = append(requestIDs, body.RequestID)
		call := len(requestIDs)
		mu.Unlock()
		if call == 1 {
			// An unavailable response is safe to retry only when the exact
			// idempotency identity is retained.
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":{"code":"SETTINGS_UNAVAILABLE","message":"retry"}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"key":"alpha","version":"2","deleted":true,"replayed":true}`))
	})
	if err := repository.Delete(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requestIDs) != 2 || requestIDs[0] != testSettingsRequestID || requestIDs[1] != testSettingsRequestID {
		t.Fatalf("request IDs = %v", requestIDs)
	}
}

func TestSettingsRepository_DeleteNotFoundAndContextCancellation(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"error":{"code":"SETTING_NOT_FOUND","message":"missing"}}`))
		})
		if err := repository.Delete(context.Background(), "missing"); !errors.Is(err, service.ErrSettingNotFound) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			t.Fatal("server must not receive a canceled request")
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := repository.Set(ctx, "alpha", "one"); err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSettingsRepository_RejectsMalformedMutationAndMapResponses(t *testing.T) {
	t.Run("invalid UTF-8 input is not rewritten by JSON encoding", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(http.ResponseWriter, *http.Request) {
			t.Fatal("invalid input must not reach the control plane")
		})
		if err := repository.Set(context.Background(), "alpha", string([]byte{0xff})); err == nil {
			t.Fatal("expected invalid UTF-8 input error")
		}
	})
	t.Run("trailing mutation response", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(`{"key":"alpha","version":"1","deleted":false,"replayed":false} {}`))
		})
		if err := repository.Set(context.Background(), "alpha", "one"); err == nil || !errors.Is(err, ErrControlPlaneUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("map includes unrequested key", func(t *testing.T) {
		repository := newSettingsTestRepository(t, func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte(`{"other":"value"}`))
		})
		if _, err := repository.GetMultiple(context.Background(), []string{"alpha"}); err == nil {
			t.Fatal("expected malformed response error")
		}
	})
}
