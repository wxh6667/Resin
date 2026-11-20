package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/topology"
)

func TestAPIContract_SubscriptionRefreshAction_E2EHTTPSource(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)

	const rawOutbound = `{"type":"shadowsocks","tag":"edge-refresh","server":"1.1.1.1","server_port":443,"method":"aes-256-gcm","password":"secret"}`
	subPayload := `{"outbounds":[` + rawOutbound + `]}`

	const userAgent = "resin-api-e2e"
	var subscriptionHits atomic.Int32
	subscriptionSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subscriptionHits.Add(1)
		if got := r.URL.Path; got != "/sub" {
			t.Fatalf("subscription path: got %q, want %q", got, "/sub")
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Fatalf("subscription user-agent: got %q, want %q", got, userAgent)
		}
		_, _ = w.Write([]byte(subPayload))
	}))
	defer subscriptionSource.Close()

	cp.Scheduler = topology.NewSubscriptionScheduler(topology.SchedulerConfig{
		SubManager: cp.SubMgr,
		Pool:       cp.Pool,
		Downloader: netutil.NewDirectDownloader(
			func() time.Duration { return 2 * time.Second },
			func() string { return userAgent },
		),
	})

	createRec := doJSONRequest(t, srv, http.MethodPost, "/api/v1/subscriptions", map[string]any{
		"name":                    "sub-e2e",
		"url":                     subscriptionSource.URL + "/sub",
		"incremental_alive_nodes": true,
	}, true)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create subscription status: got %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	createBody := decodeJSONMap(t, createRec)
	subID, _ := createBody["id"].(string)
	if subID == "" {
		t.Fatalf("create subscription missing id: body=%s", createRec.Body.String())
	}
	if got := createBody["node_count"]; got != float64(0) {
		t.Fatalf("create subscription node_count: got %v, want %v", got, 0)
	}
	if got := createBody["healthy_node_count"]; got != float64(0) {
		t.Fatalf("create subscription healthy_node_count: got %v, want %v", got, 0)
	}
	if got := createBody["incremental_alive_nodes"]; got != true {
		t.Fatalf("create subscription incremental_alive_nodes: got %v, want %v", got, true)
	}

	refreshRec := doJSONRequest(
		t,
		srv,
		http.MethodPost,
		"/api/v1/subscriptions/"+subID+"/actions/refresh",
		nil,
		true,
	)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh subscription status: got %d, want %d, body=%s", refreshRec.Code, http.StatusOK, refreshRec.Body.String())
	}
	refreshBody := decodeJSONMap(t, refreshRec)
	if refreshBody["status"] != "ok" {
		t.Fatalf("refresh response status: got %v, want ok", refreshBody["status"])
	}
	pullDeadline := time.Now().Add(5 * time.Second)
	for subscriptionHits.Load() == 0 {
		if time.Now().After(pullDeadline) {
			t.Fatal("subscription HTTP source was not requested")
		}
		time.Sleep(10 * time.Millisecond)
	}

	subBody := waitForSubscriptionNodeCount(t, srv, subID, 1)
	if got, _ := subBody["id"].(string); got != subID {
		t.Fatalf("subscription id: got %q, want %q", got, subID)
	}
	lastChecked, _ := subBody["last_checked"].(string)
	if strings.TrimSpace(lastChecked) == "" {
		t.Fatal("last_checked should be non-empty after refresh")
	}
	lastUpdated, _ := subBody["last_updated"].(string)
	if strings.TrimSpace(lastUpdated) == "" {
		t.Fatal("last_updated should be non-empty after refresh")
	}
	if v, ok := subBody["last_error"]; ok {
		if s, _ := v.(string); s != "" {
			t.Fatalf("last_error should be empty after successful refresh, got %q", s)
		}
	}
	if got := subBody["healthy_node_count"]; got != float64(0) {
		t.Fatalf("subscription healthy_node_count after refresh: got %v, want %v", got, 0)
	}

	nodesRec := doJSONRequest(t, srv, http.MethodGet, "/api/v1/nodes?subscription_id="+subID, nil, true)
	if nodesRec.Code != http.StatusOK {
		t.Fatalf("list nodes by subscription status: got %d, want %d, body=%s", nodesRec.Code, http.StatusOK, nodesRec.Body.String())
	}
	nodesBody := decodeJSONMap(t, nodesRec)
	items, ok := nodesBody["items"].([]any)
	if !ok {
		t.Fatalf("items type: got %T", nodesBody["items"])
	}
	if len(items) != 1 {
		t.Fatalf("expected exactly 1 node after refresh, got %d, body=%s", len(items), nodesRec.Body.String())
	}

	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("node item type: got %T", items[0])
	}
	wantHash := node.HashFromRawOptions([]byte(rawOutbound)).Hex()
	gotHash, _ := item["node_hash"].(string)
	if gotHash != wantHash {
		t.Fatalf("node hash: got %q, want %q", gotHash, wantHash)
	}
}

func TestAPIContract_SubscriptionRefreshAction_E2ELocalSource(t *testing.T) {
	srv, _, _ := newControlPlaneTestServer(t)

	const rawOutbound = `{"type":"shadowsocks","tag":"edge-local","server":"1.1.1.1","server_port":443,"method":"aes-256-gcm","password":"secret"}`
	localContent := `{"outbounds":[` + rawOutbound + `]}`

	createRec := doJSONRequest(t, srv, http.MethodPost, "/api/v1/subscriptions", map[string]any{
		"name":        "sub-local-e2e",
		"source_type": "local",
		"content":     localContent,
	}, true)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create local subscription status: got %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	createBody := decodeJSONMap(t, createRec)
	subID, _ := createBody["id"].(string)
	if subID == "" {
		t.Fatalf("create local subscription missing id: body=%s", createRec.Body.String())
	}
	if got, _ := createBody["source_type"].(string); got != "local" {
		t.Fatalf("create local source_type: got %q, want %q", got, "local")
	}

	refreshRec := doJSONRequest(
		t,
		srv,
		http.MethodPost,
		"/api/v1/subscriptions/"+subID+"/actions/refresh",
		nil,
		true,
	)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh local subscription status: got %d, want %d, body=%s", refreshRec.Code, http.StatusOK, refreshRec.Body.String())
	}

	subBody := waitForSubscriptionNodeCount(t, srv, subID, 1)
	if got, _ := subBody["last_error"].(string); got != "" {
		t.Fatalf("local subscription last_error: got %q, want empty", got)
	}
}

// waitForSubscriptionNodeCount polls until a background refresh has applied
// the expected number of nodes.
func waitForSubscriptionNodeCount(t *testing.T, srv *Server, subID string, want int) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec := doJSONRequest(t, srv, http.MethodGet, "/api/v1/subscriptions/"+subID, nil, true)
		if rec.Code == http.StatusOK {
			body := decodeJSONMap(t, rec)
			if got, ok := body["node_count"].(float64); ok && int(got) == want {
				return body
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for subscription %s node_count=%d", subID, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForSingleNodeWithOutbound polls until the subscription has exactly one
// node whose outbound is ready.
func waitForSingleNodeWithOutbound(t *testing.T, srv *Server, subID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		nodesRec := doJSONRequest(t, srv, http.MethodGet, "/api/v1/nodes?subscription_id="+subID, nil, true)
		if nodesRec.Code == http.StatusOK {
			nodesBody := decodeJSONMap(t, nodesRec)
			if items, ok := nodesBody["items"].([]any); ok && len(items) == 1 {
				if item, ok := items[0].(map[string]any); ok {
					if hasOutbound, _ := item["has_outbound"].(bool); hasOutbound {
						return item
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a refreshed node with outbound")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
