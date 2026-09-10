//go:build unit

package service

import (
	"sync"
	"testing"
)

func TestAccountHotCachesConcurrentAccess(t *testing.T) {
	account := &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"model_mapping": map[string]any{
				"client-model": "upstream-model",
			},
			credKeyHeaderOverrideEnabled: true,
			credKeyHeaderOverrides: map[string]any{
				"x-client": "sub2api",
			},
		},
	}

	const (
		workers    = 32
		iterations = 100
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				if got := account.GetModelMapping()["client-model"]; got != "upstream-model" {
					t.Errorf("unexpected model mapping: %q", got)
					return
				}
				if got := account.GetHeaderOverrides()["x-client"]; got != "sub2api" {
					t.Errorf("unexpected header override: %q", got)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}
