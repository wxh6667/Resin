package verified

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/testutil"
	"github.com/Resinat/Resin/internal/topology"
)

const (
	ssRaw = `{"type":"shadowsocks","tag":"ss-1","server":"192.0.2.10","server_port":8388,` +
		`"method":"aes-128-gcm","password":"secret"}`
	vmessRaw = `{"type":"vmess","tag":"vm-1","server":"192.0.2.11","server_port":443,` +
		`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto","alter_id":0}`
	httpRaw    = `{"type":"http","tag":"h-1","server":"192.0.2.12","server_port":8080}`
	staleSSRaw = `{"type":"shadowsocks","tag":"ss-old","server":"192.0.2.13","server_port":8388,` +
		`"method":"aes-128-gcm","password":"secret"}`
	circuitSSRaw = `{"type":"shadowsocks","tag":"ss-open","server":"192.0.2.14","server_port":8388,` +
		`"method":"aes-128-gcm","password":"secret"}`
	noOutSSRaw = `{"type":"shadowsocks","tag":"ss-noob","server":"192.0.2.15","server_port":8388,` +
		`"method":"aes-128-gcm","password":"secret"}`
)

type poolNodeSpec struct {
	raw     string
	probeAt time.Time
	open    bool
	noOut   bool
}

func buildPool(t *testing.T, nodes []poolNodeSpec) *topology.GlobalNodePool {
	t.Helper()
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		MaxConsecutiveFailures: func() int { return 3 },
		MaxLatencyTableEntries: 8,
	})
	for _, spec := range nodes {
		raw := json.RawMessage(spec.raw)
		hash := node.HashFromRawOptions(raw)
		pool.AddNodeFromSub(hash, raw, "sub-1")
		entry, ok := pool.GetEntry(hash)
		if !ok {
			t.Fatalf("node %s missing from pool", hash.Hex())
		}
		if !spec.noOut {
			ob := testutil.NewNoopOutbound()
			entry.Outbound.Store(&ob)
		}
		entry.CircuitOpenSince.Store(0)
		if spec.open {
			entry.CircuitOpenSince.Store(time.Now().UnixNano())
		}
		if !spec.probeAt.IsZero() {
			entry.LastLatencyProbeAttempt.Store(spec.probeAt.UnixNano())
		}
	}
	return pool
}

func TestBuildBatchFiltersAndEncodes(t *testing.T) {
	now := time.Now()
	pool := buildPool(t, []poolNodeSpec{
		{raw: ssRaw, probeAt: now.Add(-10 * time.Minute)},
		{raw: vmessRaw, probeAt: now.Add(-10 * time.Minute)},
		{raw: httpRaw, probeAt: now.Add(-10 * time.Minute)},
		{raw: staleSSRaw, probeAt: now.Add(-3 * time.Hour)},
		{raw: circuitSSRaw, probeAt: now.Add(-10 * time.Minute), open: true},
		{raw: noOutSSRaw, probeAt: now.Add(-10 * time.Minute), noOut: true},
	})
	uploader, err := NewUploader(Config{
		Endpoint: "https://example.com/upload/verified",
		Token:    "token",
		Window:   2 * time.Hour,
	}, pool, nil)
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}

	body, stats, err := uploader.BuildBatch(now)
	if err != nil {
		t.Fatalf("BuildBatch: %v", err)
	}
	want := Stats{Pool: 6, Eligible: 4, Stale: 1, Unsupported: 1, Records: 2}
	if stats != want {
		t.Fatalf("stats = %+v, want %+v", stats, want)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("batch lines = %d, want 2", len(lines))
	}
	fingerprints := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("unmarshal record %q: %v", line, err)
		}
		if record.Fingerprint != Fingerprint(record.RawURI) {
			t.Fatalf("fingerprint %q does not match raw_uri %q", record.Fingerprint, record.RawURI)
		}
		if !strings.HasPrefix(record.RawURI, "ss://") && !strings.HasPrefix(record.RawURI, "vmess://") {
			t.Fatalf("unexpected raw_uri scheme: %q", record.RawURI)
		}
		if record.CheckedAt == "" {
			t.Fatalf("record %q has empty checked_at", record.RawURI)
		}
		fingerprints[record.Fingerprint] = struct{}{}
	}
	if len(fingerprints) != 2 {
		t.Fatalf("unique fingerprints = %d, want 2", len(fingerprints))
	}
}

func TestUploadSendsReceiverCompatibleRequest(t *testing.T) {
	now := time.Now()
	pool := buildPool(t, []poolNodeSpec{
		{raw: ssRaw, probeAt: now.Add(-10 * time.Minute)},
		{raw: vmessRaw, probeAt: now.Add(-10 * time.Minute)},
	})

	var captured struct {
		auth     string
		mime     string
		checksum string
		window   string
		body     []byte
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.auth = r.Header.Get("Authorization")
		captured.mime = r.Header.Get("Content-Type")
		captured.checksum = r.Header.Get("X-Verified-SHA256")
		captured.window = r.Header.Get("X-Verified-Window-Minutes")
		captured.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"total":2,"skipped_invalid":0,"duplicates":0}`)
	}))
	defer server.Close()

	uploader, err := NewUploader(Config{
		Endpoint:   server.URL,
		Token:      "upload-token",
		Window:     2 * time.Hour,
		Timeout:    5 * time.Second,
		HTTPClient: server.Client(),
	}, pool, func(*node.NodeEntry) (float64, bool) { return 42.5, true })
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}
	uploader.now = func() time.Time { return now }

	stats, err := uploader.Upload(context.Background())
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if stats.Records != 2 {
		t.Fatalf("records = %d, want 2", stats.Records)
	}
	if captured.auth != "Bearer upload-token" {
		t.Fatalf("authorization = %q", captured.auth)
	}
	if captured.mime != "application/gzip" {
		t.Fatalf("content-type = %q, want application/gzip", captured.mime)
	}
	if captured.window != "120" {
		t.Fatalf("window header = %q, want 120", captured.window)
	}

	reader, err := gzip.NewReader(bytes.NewReader(captured.body))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	sum := sha256.Sum256(plain)
	if captured.checksum != hex.EncodeToString(sum[:]) {
		t.Fatalf("X-Verified-SHA256 = %q, want %x", captured.checksum, sum)
	}
	lines := strings.Split(strings.TrimSpace(string(plain)), "\n")
	if len(lines) != 2 {
		t.Fatalf("uploaded lines = %d, want 2", len(lines))
	}
	for _, line := range lines {
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("unmarshal uploaded record: %v", err)
		}
		if record.LatencyMS == nil || *record.LatencyMS != 42.5 {
			t.Fatalf("latency_ms = %v, want 42.5", record.LatencyMS)
		}
	}
}

func TestUploadUnauthorizedIsNotRetried(t *testing.T) {
	now := time.Now()
	pool := buildPool(t, []poolNodeSpec{{raw: ssRaw, probeAt: now.Add(-time.Minute)}})

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	uploader, err := NewUploader(Config{
		Endpoint:   server.URL,
		Token:      "wrong-token",
		Window:     time.Hour,
		Timeout:    time.Second,
		HTTPClient: server.Client(),
	}, pool, nil)
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}
	uploader.now = func() time.Time { return now }

	if _, err := uploader.Upload(context.Background()); err == nil {
		t.Fatal("Upload succeeded, want 401 error")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (401 must not be retried)", got)
	}
}

func TestUploadRetriesServerErrors(t *testing.T) {
	now := time.Now()
	pool := buildPool(t, []poolNodeSpec{{raw: ssRaw, probeAt: now.Add(-time.Minute)}})

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"total":1}`)
	}))
	defer server.Close()

	uploader, err := NewUploader(Config{
		Endpoint:   server.URL,
		Token:      "token",
		Window:     time.Hour,
		Timeout:    time.Second,
		HTTPClient: server.Client(),
	}, pool, nil)
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}
	uploader.now = func() time.Time { return now }

	if _, err := uploader.Upload(context.Background()); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 (two 500s then success)", got)
	}
}

func TestFingerprintIgnoresFragmentAndTrailingSlash(t *testing.T) {
	withFragment := Fingerprint("ss://YWJj@192.0.2.10:8388#display-name")
	withSlash := Fingerprint("ss://YWJj@192.0.2.10:8388/")
	sum := sha256.Sum256([]byte("ss://YWJj@192.0.2.10:8388"))
	want := hex.EncodeToString(sum[:])
	if withFragment != want || withSlash != want {
		t.Fatalf("fingerprint fragment=%q slash=%q, want %q", withFragment, withSlash, want)
	}
}

func TestDisabledUploaderNoOps(t *testing.T) {
	uploader, err := NewUploader(Config{Window: time.Hour}, nil, nil)
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}
	if uploader.Enabled() {
		t.Fatal("uploader without endpoint must be disabled")
	}
	stats, err := uploader.Upload(context.Background())
	if err != nil || stats != (Stats{}) {
		t.Fatalf("Upload on disabled uploader = %+v, %v", stats, err)
	}
}

func TestNewUploaderRejectsInvalidConfig(t *testing.T) {
	if _, err := NewUploader(Config{Endpoint: "not-a-url", Token: "t"}, nil, nil); err == nil {
		t.Fatal("want error for non-URL endpoint")
	}
	if _, err := NewUploader(Config{Endpoint: "https://example.com/x"}, nil, nil); err == nil {
		t.Fatal("want error for missing token")
	}
}

func TestStatusTracksAttempts(t *testing.T) {
	now := time.Now()
	pool := buildPool(t, []poolNodeSpec{{raw: ssRaw, probeAt: now.Add(-time.Minute)}})

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"total":1,"skipped_invalid":0}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	uploader, err := NewUploader(Config{
		Endpoint:   server.URL,
		Token:      "token",
		Window:     time.Hour,
		Timeout:    time.Second,
		HTTPClient: server.Client(),
	}, pool, nil)
	if err != nil {
		t.Fatalf("NewUploader: %v", err)
	}
	uploader.now = func() time.Time { return now }

	if _, err := uploader.Upload(context.Background()); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	status := uploader.Status()
	if !status.Enabled || status.Running {
		t.Fatalf("status enabled/running = %v/%v", status.Enabled, status.Running)
	}
	if status.LastSuccessAt == "" || status.LastAttemptAt == "" {
		t.Fatalf("missing timestamps: %+v", status)
	}
	if len(status.History) != 1 || status.History[0].Records != 1 {
		t.Fatalf("history = %+v", status.History)
	}
	if !strings.Contains(status.History[0].Response, "total") {
		t.Fatalf("history response = %q", status.History[0].Response)
	}

	if _, err := uploader.Upload(context.Background()); err == nil {
		t.Fatal("second upload succeeded, want 401")
	}
	status = uploader.Status()
	if status.LastError == "" {
		t.Fatal("LastError empty after failed upload")
	}
	if len(status.History) != 2 || status.History[0].Error == "" {
		t.Fatalf("history after failure = %+v", status.History)
	}
	if status.History[1].Error != "" {
		t.Fatalf("previous attempt error overwritten: %+v", status.History[1])
	}
}

func TestNilUploaderStatus(t *testing.T) {
	var uploader *Uploader
	status := uploader.Status()
	if status.Enabled || len(status.History) != 0 {
		t.Fatalf("nil status = %+v", status)
	}
}
