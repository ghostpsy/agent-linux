//go:build linux

package main

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"
)

// maxIngestResponseBodyBytes caps response body reads to avoid OOM on hostile servers.
const maxIngestResponseBodyBytes int64 = 1 << 20

// postIngest POSTs JSON to {apiBaseURL}/v1/ingest with a Bearer token.
func postIngest(ctx context.Context, apiBaseURL, token string, body []byte) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	url := strings.TrimSuffix(apiBaseURL, "/") + "/v1/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 60 * time.Second}
	return client.Do(req)
}
