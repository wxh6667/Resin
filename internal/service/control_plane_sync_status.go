package service

import (
	"github.com/Resinat/Resin/internal/topology"
	"github.com/Resinat/Resin/internal/verified"
)

// SyncStatusResponse combines pull metrics and verified-upload status for the
// control-plane status page.
type SyncStatusResponse struct {
	Upload    verified.Status         `json:"upload"`
	Refreshes []topology.RefreshStats `json:"refreshes"`
}

// SyncStatus returns the current pull and upload status. It is safe to call
// when the uploader or scheduler are not configured.
func (s *ControlPlaneService) SyncStatus() SyncStatusResponse {
	resp := SyncStatusResponse{Refreshes: []topology.RefreshStats{}}
	if s == nil {
		return resp
	}
	resp.Upload = s.VerifiedUploader.Status()
	if s.Scheduler != nil {
		resp.Refreshes = s.Scheduler.RefreshStatsSnapshot()
	}
	return resp
}
