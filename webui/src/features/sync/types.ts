export type UploadAttempt = {
  started_at: string;
  finished_at: string;
  duration_ms: number;
  records: number;
  eligible: number;
  stale: number;
  unsupported: number;
  duplicates: number;
  error?: string;
  response?: string;
};

export type UploadStatus = {
  enabled: boolean;
  endpoint: string;
  window_seconds: number;
  timeout_seconds: number;
  running: boolean;
  last_attempt_at?: string;
  last_success_at?: string;
  last_error?: string;
  history: UploadAttempt[];
};

export type RefreshStats = {
  subscription_id: string;
  subscription_name: string;
  in_flight: boolean;
  started_at?: string;
  finished_at?: string;
  fetch_ms: number;
  parse_ms: number;
  apply_ms: number;
  bytes: number;
  parsed: number;
  added: number;
  kept: number;
  kept_unchanged: number;
  removed: number;
  error?: string;
};

export type SyncStatus = {
  upload: UploadStatus;
  refreshes: RefreshStats[];
};
