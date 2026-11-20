import { apiRequest } from "../../lib/api-client";
import type { SyncStatus } from "./types";

export function getSyncStatus(): Promise<SyncStatus> {
  return apiRequest<SyncStatus>("/api/v1/sync/status");
}
