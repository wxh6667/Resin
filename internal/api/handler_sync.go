package api

import (
	"net/http"

	"github.com/Resinat/Resin/internal/service"
)

// HandleSyncStatus returns the pull and verified-upload status.
func HandleSyncStatus(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, cp.SyncStatus())
	}
}
