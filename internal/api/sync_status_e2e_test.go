package api

import (
	"net/http"
	"testing"
)

func TestAPIContract_SyncStatus(t *testing.T) {
	srv, _, _ := newControlPlaneTestServer(t)

	rec := doJSONRequest(t, srv, http.MethodGet, "/api/v1/sync/status", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync status: got %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeJSONMap(t, rec)
	upload, ok := body["upload"].(map[string]any)
	if !ok {
		t.Fatalf("upload type: got %T", body["upload"])
	}
	if _, ok := upload["enabled"]; !ok {
		t.Fatalf("upload.enabled missing: %v", upload)
	}
	if _, ok := upload["history"].([]any); !ok {
		t.Fatalf("upload.history type: got %T", upload["history"])
	}
	if _, ok := body["refreshes"].([]any); !ok {
		t.Fatalf("refreshes type: got %T", body["refreshes"])
	}
}
