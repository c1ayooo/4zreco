package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/norma/llm"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestIsQuotaExhaustedMessage(t *testing.T) {
	t.Parallel()
	positive := []string{
		`{"error":{"code":"insufficient_quota"}}`,
		`RESOURCE_EXHAUSTED`,
		`You exceeded your current quota, please check your plan and billing details.`,
		`billing_not_active`,
		`credit balance is too low`,
		`账户余额不足，请充值`,
	}
	for _, message := range positive {
		if !IsQuotaExhaustedMessage(message) {
			t.Errorf("expected quota classification for %q", message)
		}
	}

	negative := []string{
		`status 429: rate limit exceeded`,
		`RESOURCE_EXHAUSTED: rate limit exceeded`,
		`too many requests per minute`,
		`quota exceeded for quota metric GenerateRequestsPerMinutePerProjectPerBaseModel`,
		`RESOURCE_EXHAUSTED: TPM quota exceeded`,
		`tokens per minute quota exceeded`,
		`rate_limit_exceeded: requests per second`,
		`status 401: invalid api key`,
		`status 401: insufficient_quota`,
		`HTTP 403: billing_hard_limit_reached`,
		`status 500: internal server error`,
		`status=503: insufficient_quota`,
		`context length exceeded`,
	}
	for _, message := range negative {
		if IsQuotaExhaustedMessage(message) {
			t.Errorf("unexpected quota classification for %q", message)
		}
	}
}

func TestQuotaAwareTransportOnlyNormalizesExplicitQuota429(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		body       string
		wantStatus int
	}{
		{name: "quota", status: http.StatusTooManyRequests, body: `{"code":"insufficient_quota"}`, wantStatus: http.StatusPaymentRequired},
		{name: "ordinary rate limit", status: http.StatusTooManyRequests, body: `{"message":"rate limit exceeded"}`, wantStatus: http.StatusTooManyRequests},
		{name: "server error", status: http.StatusInternalServerError, body: `insufficient_quota`, wantStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := quotaAwareTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tt.status,
					Status:     http.StatusText(tt.status),
					Body:       io.NopCloser(strings.NewReader(tt.body)),
					Header:     make(http.Header),
				}, nil
			})}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.invalid", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tt.wantStatus)
			}
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotBody) != tt.body {
				t.Fatalf("body=%q, want %q", gotBody, tt.body)
			}
		})
	}
}

func TestProviderDoesNotRetryExplicitQuota429(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`)
	}))
	defer upstream.Close()

	provider, err := ConfigFrom("openai", "test-model", upstream.URL, "test-key", "").NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	var streamErr error
	for _, err := range provider.Stream(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("ping")},
	}) {
		if err != nil {
			streamErr = err
		}
	}
	if streamErr == nil || !IsQuotaExhaustedMessage(streamErr.Error()) {
		t.Fatalf("expected explicit quota error, got %v", streamErr)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("explicit quota request retried %d times, want exactly one request", got)
	}
}

func TestQuotaAwareTransportAdaptiveThrottle(t *testing.T) {
	t.Parallel()

	// 场景：首发 429(RPM)，其后全部 200。第二发必须被自适应闸延迟 ≥ gapStart。
	var reqs atomic.Int64
	base := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		n := reqs.Add(1)
		st := http.StatusOK
		if n == 1 {
			st = http.StatusTooManyRequests
		}
		return &http.Response{
			StatusCode: st, Status: http.StatusText(st),
			Body:   io.NopCloser(strings.NewReader(`{"error":{"message":"group requests-per-minute limit exceeded"}}`)),
			Header: make(http.Header),
		}, nil
	})
	tr := quotaAwareTransport{base: base, gov: newAdaptiveGovernor(nil)}
	tr.gov.params = adaptiveParams{start: 120 * time.Millisecond, max: 300 * time.Millisecond, ease: 8}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.invalid", nil)

	if _, err := tr.RoundTrip(req); err != nil { // 首发：429，触发收紧
		t.Fatalf("first trip: %v", err)
	}
	start := time.Now()
	if _, err := tr.RoundTrip(req); err != nil { // 第二发：应等待 ~gapStart
		t.Fatalf("second trip: %v", err)
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("second request must be throttled to ≥120ms, elapsed %v", el)
	}

	// 成功连胜 → 间距减半直至解除；解除后请求不再被延迟
	for i := 0; i < 2*adaptiveOkToEase; i++ {
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("ease trip %d: %v", i, err)
		}
	}
	if tr.gov.gap() != 0 {
		t.Fatalf("sustained success must fully lift the gap, got %v", tr.gov.gap())
	}
	start = time.Now()
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("post-ease trip: %v", err)
	}
	if el := time.Since(start); el > 20*time.Millisecond {
		t.Fatalf("lifted governor must not delay, elapsed %v", el)
	}
}

func TestQuotaAwareTransportRetryAfterFloor(t *testing.T) {
	t.Parallel()
	base := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		h := make(http.Header)
		h.Set("Retry-After", "1")
		return &http.Response{
			StatusCode: http.StatusTooManyRequests, Status: "429",
			Body: io.NopCloser(strings.NewReader(`{"error":{"message":"rate limit exceeded"}}`)), Header: h,
		}, nil
	})
	tr := quotaAwareTransport{base: base, gov: newAdaptiveGovernor(nil)}
	tr.gov.params = adaptiveParams{start: 10 * time.Millisecond, max: time.Minute, ease: 8}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.invalid", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("first trip: %v", err)
	}
	if got := tr.gov.gap(); got != time.Second {
		t.Fatalf("Retry-After must floor the gap to 1s, got %v", got)
	}
}

func TestQuotaAwareTransportQuota429AlsoThrottles(t *testing.T) {
	t.Parallel()
	// 余额耗尽型 429（会被归一成 402）同样要收紧自适应间距
	base := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests, Status: "429",
			Body:   io.NopCloser(strings.NewReader(`{"error":{"code":"insufficient_quota"}}`)),
			Header: make(http.Header),
		}, nil
	})
	tr := quotaAwareTransport{base: base, gov: newAdaptiveGovernor(nil)}
	tr.gov.params = adaptiveParams{start: 120 * time.Millisecond, max: time.Second, ease: 8}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.invalid", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("trip: %v", err)
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("quota 429 must normalize to 402, got %d", resp.StatusCode)
	}
	if tr.gov.gap() != 120*time.Millisecond {
		t.Fatalf("quota-style rejection must tighten the governor, got %v", tr.gov.gap())
	}
}
