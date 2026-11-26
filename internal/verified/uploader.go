// Package verified uploads locally verified, healthy proxy nodes to an
// external receiver (the detection backflow endpoint), so downstream
// subscribers can consume the validated pool.
package verified

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/subscription"
	"github.com/Resinat/Resin/internal/topology"
)

const (
	defaultWindow  = 2 * time.Hour
	defaultTimeout = 30 * time.Second
	maxAttempts    = 3
	maxHistory     = 50
)

// Attempt records one upload run.
type Attempt struct {
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	DurationMS  int64  `json:"duration_ms"`
	Records     int    `json:"records"`
	Eligible    int    `json:"eligible"`
	Stale       int    `json:"stale"`
	Unsupported int    `json:"unsupported"`
	Duplicates  int    `json:"duplicates"`
	Error       string `json:"error,omitempty"`
	Response    string `json:"response,omitempty"`
}

// Status is a JSON-friendly snapshot of the uploader for the control plane.
type Status struct {
	Enabled        bool      `json:"enabled"`
	Endpoint       string    `json:"endpoint"`
	WindowSeconds  int64     `json:"window_seconds"`
	TimeoutSeconds int64     `json:"timeout_seconds"`
	Running        bool      `json:"running"`
	LastAttemptAt  string    `json:"last_attempt_at,omitempty"`
	LastSuccessAt  string    `json:"last_success_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	History        []Attempt `json:"history"`
}

// Config configures the verified-node uploader.
type Config struct {
	// Endpoint is the POST target (e.g.
	// https://node-harvester.easyetsy.top/upload/verified). Empty disables
	// uploading.
	Endpoint string
	// Token is the bearer token required by the receiver. It must come from
	// the environment and must never be logged or persisted by Resin.
	Token string
	// Window is the detection freshness window. Nodes whose latest probe
	// attempt is older than this are not uploaded, and the same value is sent
	// as X-Verified-Window-Minutes.
	Window time.Duration
	// Timeout bounds a single upload attempt.
	Timeout time.Duration
	// HTTPClient optionally overrides the HTTP client (tests).
	HTTPClient *http.Client
}

// Record is one line of the uploaded JSONL body.
type Record struct {
	Fingerprint string   `json:"fingerprint"`
	RawURI      string   `json:"raw_uri"`
	CheckedAt   string   `json:"checked_at"`
	EgressIP    string   `json:"egress_ip,omitempty"`
	Region      string   `json:"region,omitempty"`
	LatencyMS   *float64 `json:"latency_ms,omitempty"`
}

// Stats describes one batch build.
type Stats struct {
	Pool        int // entries scanned in the pool
	Eligible    int // healthy + enabled entries
	Stale       int // eligible entries without a probe attempt inside the window
	Unsupported int // entries whose outbound type has no share-URI form
	Duplicates  int // entries deduplicated by fingerprint
	Records     int // records written into the batch
}

// Uploader periodically (on demand) uploads the healthy subset of the pool.
// Trigger coalesces concurrent requests: at most one upload runs at a time,
// and one pending trigger is remembered while an upload is in flight.
type Uploader struct {
	cfg       Config
	pool      *topology.GlobalNodePool
	latencyMS func(*node.NodeEntry) (float64, bool)
	client    *http.Client
	now       func() time.Time

	running  atomic.Bool
	pending  atomic.Bool
	inFlight atomic.Int32

	statusMu    sync.Mutex
	history     []Attempt
	lastAttempt *Attempt
	lastSuccess string
	lastError   string
}

// NewUploader creates an uploader. It returns an error only when the
// configured endpoint/token are inconsistent.
func NewUploader(cfg Config, pool *topology.GlobalNodePool, latencyMS func(*node.NodeEntry) (float64, bool)) (*Uploader, error) {
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Window <= 0 {
		cfg.Window = defaultWindow
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Endpoint != "" {
		parsed, err := url.Parse(cfg.Endpoint)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("verified upload endpoint must be an absolute http(s) URL")
		}
		if cfg.Token == "" {
			return nil, fmt.Errorf("verified upload token is required when an endpoint is configured")
		}
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Uploader{
		cfg:       cfg,
		pool:      pool,
		latencyMS: latencyMS,
		client:    client,
		now:       time.Now,
	}, nil
}

// Enabled reports whether the uploader has a usable endpoint and token.
func (u *Uploader) Enabled() bool {
	return u != nil && u.cfg.Endpoint != "" && u.cfg.Token != ""
}

// Trigger starts an upload in the background. Concurrent triggers coalesce.
func (u *Uploader) Trigger() {
	if !u.Enabled() {
		return
	}
	go u.run()
}

func (u *Uploader) run() {
	if !u.running.CompareAndSwap(false, true) {
		u.pending.Store(true)
		return
	}
	for {
		u.pending.Store(false)
		if _, err := u.Upload(context.Background()); err != nil {
			log.Printf("[verified-upload] %v", err)
		}
		if u.pending.Load() {
			continue
		}
		u.running.Store(false)
		// Close the lost-wakeup window between the two stores above.
		if u.pending.Load() && u.running.CompareAndSwap(false, true) {
			continue
		}
		return
	}
}

// Fingerprint is the receiver-compatible node identity: sha256 over the URI
// with the display-name fragment and trailing slashes removed.
func Fingerprint(uri string) string {
	base, _, _ := strings.Cut(uri, "#")
	base = strings.TrimRight(base, "/")
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

// BuildBatch renders the current healthy-and-fresh pool as JSONL records.
func (u *Uploader) BuildBatch(now time.Time) ([]byte, Stats, error) {
	if u.pool == nil {
		return nil, Stats{}, fmt.Errorf("verified upload: nil node pool")
	}
	cutoff := now.Add(-u.cfg.Window).UnixNano()
	evaluate := u.pool.MakeHealthyAndEnabledEvaluator()

	seen := make(map[string]struct{})
	var body bytes.Buffer
	var stats Stats
	var encodeErr error

	u.pool.Range(func(_ node.Hash, entry *node.NodeEntry) bool {
		stats.Pool++
		if entry == nil || !evaluate(entry) {
			return true
		}
		stats.Eligible++

		checkedNs := entry.LastLatencyProbeAttempt.Load()
		if egressAttemptNs := entry.LastEgressUpdateAttempt.Load(); egressAttemptNs > checkedNs {
			checkedNs = egressAttemptNs
		}
		if checkedNs < cutoff {
			stats.Stale++
			return true
		}

		uri, ok := subscription.ShareURI(entry.RawOptions)
		if !ok {
			stats.Unsupported++
			return true
		}
		fingerprint := Fingerprint(uri)
		if _, dup := seen[fingerprint]; dup {
			stats.Duplicates++
			return true
		}
		seen[fingerprint] = struct{}{}

		record := Record{
			Fingerprint: fingerprint,
			CheckedAt:   time.Unix(0, checkedNs).UTC().Format(time.RFC3339Nano),
		}
		if egressIP := entry.GetEgressIP(); egressIP.IsValid() {
			record.EgressIP = egressIP.String()
		}
		record.Region = entry.GetRegion(nil)
		if u.latencyMS != nil {
			if ms, ok := u.latencyMS(entry); ok {
				record.LatencyMS = &ms
			}
		}
		// Replace the original subscription tag with Resin's own probe
		// results so downstream clients see "<COUNTRY>-<SCORE>-<EGRESS_IP>".
		// The fingerprint ignores the fragment, so node identity is unchanged.
		record.RawURI = uriWithDisplayName(uri, uploadDisplayName(record.Region, record.EgressIP, record.LatencyMS))
		line, err := json.Marshal(record)
		if err != nil {
			encodeErr = err
			return false
		}
		body.Write(line)
		body.WriteByte('\n')
		stats.Records++
		return true
	})
	if encodeErr != nil {
		return nil, stats, encodeErr
	}
	return body.Bytes(), stats, nil
}

// Upload builds a batch and posts it once (with retries for retryable
// failures). It is a no-op when the uploader is disabled.
func (u *Uploader) Upload(ctx context.Context) (Stats, error) {
	if !u.Enabled() {
		return Stats{}, nil
	}
	started := u.now()
	u.inFlight.Add(1)
	defer u.inFlight.Add(-1)

	stats, response, err := u.uploadBatch(ctx, started)
	u.recordAttempt(started, u.now(), stats, response, err)
	return stats, err
}

func (u *Uploader) uploadBatch(ctx context.Context, started time.Time) (Stats, string, error) {
	body, stats, err := u.BuildBatch(started)
	if err != nil {
		return stats, "", err
	}
	if stats.Records == 0 {
		log.Printf(
			"[verified-upload] no eligible nodes within window %s (pool=%d eligible=%d stale=%d unsupported=%d); skipping",
			u.cfg.Window, stats.Pool, stats.Eligible, stats.Stale, stats.Unsupported,
		)
		return stats, "", nil
	}
	log.Printf(
		"[verified-upload] uploading %d records (eligible=%d stale=%d unsupported=%d duplicates=%d)",
		stats.Records, stats.Eligible, stats.Stale, stats.Unsupported, stats.Duplicates,
	)

	compressed, err := gzipBytes(body)
	if err != nil {
		return stats, "", fmt.Errorf("verified upload: gzip batch: %w", err)
	}
	checksum := sha256.Sum256(body)
	response, err := u.postWithRetry(ctx, compressed, hex.EncodeToString(checksum[:]))
	if err != nil {
		return stats, response, err
	}
	log.Printf(
		"[verified-upload] uploaded %d records in %s",
		stats.Records, u.now().Sub(started).Round(time.Millisecond),
	)
	return stats, response, nil
}

func (u *Uploader) recordAttempt(started, finished time.Time, stats Stats, response string, err error) {
	attempt := Attempt{
		StartedAt:   started.UTC().Format(time.RFC3339Nano),
		FinishedAt:  finished.UTC().Format(time.RFC3339Nano),
		DurationMS:  finished.Sub(started).Milliseconds(),
		Records:     stats.Records,
		Eligible:    stats.Eligible,
		Stale:       stats.Stale,
		Unsupported: stats.Unsupported,
		Duplicates:  stats.Duplicates,
		Response:    truncate(response, 300),
	}
	if err != nil {
		attempt.Error = err.Error()
	}

	u.statusMu.Lock()
	defer u.statusMu.Unlock()
	if err != nil {
		u.lastError = err.Error()
	} else {
		u.lastError = ""
		u.lastSuccess = attempt.FinishedAt
	}
	u.lastAttempt = &attempt
	u.history = append([]Attempt{attempt}, u.history...)
	if len(u.history) > maxHistory {
		u.history = u.history[:maxHistory]
	}
}

// Status returns a concurrency-safe snapshot for the control plane.
func (u *Uploader) Status() Status {
	if u == nil {
		return Status{History: []Attempt{}}
	}
	u.statusMu.Lock()
	defer u.statusMu.Unlock()

	status := Status{
		Enabled:        u.Enabled(),
		Endpoint:       u.cfg.Endpoint,
		WindowSeconds:  int64(u.cfg.Window / time.Second),
		TimeoutSeconds: int64(u.cfg.Timeout / time.Second),
		Running:        u.running.Load() || u.inFlight.Load() > 0,
		LastSuccessAt:  u.lastSuccess,
		LastError:      u.lastError,
		History:        append([]Attempt{}, u.history...),
	}
	if u.lastAttempt != nil {
		status.LastAttemptAt = u.lastAttempt.FinishedAt
	}
	return status
}

// uploadDisplayName renders the receiver-facing node alias from Resin's own
// probe results: "<COUNTRY>-<SCORE>-<EGRESS_IP>". Country is the upper-cased
// probed egress region ("XX" when unknown). Score is a 0-100 quality scale
// derived from the measured EWMA latency, higher is better; unknown latency
// renders 0.
func uploadDisplayName(region, egressIP string, latencyMS *float64) string {
	country := strings.ToUpper(strings.TrimSpace(region))
	if country == "" {
		country = "XX"
	}
	score := 0
	if latencyMS != nil && *latencyMS > 0 {
		score = int(math.Round(100 - *latencyMS/10))
		switch {
		case score < 0:
			score = 0
		case score > 100:
			score = 100
		}
	}
	name := country + "-" + strconv.Itoa(score)
	if ip := strings.TrimSpace(egressIP); ip != "" {
		name += "-" + ip
	}
	return name
}

// uriWithDisplayName swaps the URI fragment (display name) without touching
// the base, so the receiver-computed fingerprint stays identical.
func uriWithDisplayName(uri, name string) string {
	base, _, _ := strings.Cut(uri, "#")
	return base + "#" + name
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (u *Uploader) postWithRetry(ctx context.Context, body []byte, checksum string) (string, error) {
	backoff := time.Second
	var lastErr error
	var lastDetail string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		retryable, detail, err := u.postOnce(ctx, body, checksum)
		lastDetail = detail
		if err == nil {
			return detail, nil
		}
		lastErr = err
		if !retryable || attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return lastDetail, fmt.Errorf("verified upload canceled: %w", ctx.Err())
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastDetail, lastErr
}

// postOnce sends the batch and reports whether the failure is retryable.
func (u *Uploader) postOnce(ctx context.Context, body []byte, checksum string) (retryable bool, detail string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("verified upload: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+u.cfg.Token)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Verified-SHA256", checksum)
	req.Header.Set("X-Verified-Window-Minutes", strconv.Itoa(int(u.cfg.Window/time.Minute)))
	req.Header.Set("User-Agent", "resin-verified-upload/1")

	resp, err := u.client.Do(req)
	if err != nil {
		return true, "", fmt.Errorf("verified upload: post batch: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail = strings.TrimSpace(string(respBody))
	switch {
	case resp.StatusCode == http.StatusOK:
		log.Printf("[verified-upload] receiver response: %s", detail)
		return false, detail, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return false, detail, fmt.Errorf("verified upload: unauthorized (401); check the upload token")
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return false, detail, fmt.Errorf("verified upload: batch exceeds receiver limit (413)")
	case resp.StatusCode >= http.StatusInternalServerError:
		return true, detail, fmt.Errorf("verified upload: server error %d: %s", resp.StatusCode, truncate(detail, 512))
	default:
		return false, detail, fmt.Errorf("verified upload: rejected with status %d: %s", resp.StatusCode, truncate(detail, 512))
	}
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
