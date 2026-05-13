"use client";

import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type {
  HuntsResponse,
  HuntSnapshot,
  AuditQueryResponse,
} from "@/lib/types";

/**
 * Poll the list of recorded hunts. Refreshes every 5s by default so new
 * hunts the operator kicks off from the CLI appear in the dashboard.
 */
export function useHunts(refetchMs = 5000) {
  return useQuery<HuntsResponse | null>({
    queryKey: ["hunts"],
    queryFn: () => apiGet<HuntsResponse>("/api/hack/hunts?limit=50"),
    refetchInterval: refetchMs,
    staleTime: 2000,
  });
}

/**
 * Aggregate snapshot of one hunt: per-phase stats, worker rollup,
 * finding rollup. Polls every 1s while the hunt is selected so the
 * dashboard reflects live swarm progress.
 *
 * Pass `null`/empty `huntId` to disable polling.
 */
export function useHuntSnapshot(huntId: string | null, refetchMs = 1500) {
  return useQuery<HuntSnapshot | null>({
    queryKey: ["hunt", huntId],
    queryFn: () =>
      huntId
        ? apiGet<HuntSnapshot>(`/api/hack/hunt?hunt_id=${encodeURIComponent(huntId)}`)
        : Promise.resolve(null),
    enabled: !!huntId,
    refetchInterval: huntId ? refetchMs : false,
    staleTime: 500,
  });
}

/**
 * Incremental audit-event tail for one hunt. Useful for the live
 * activity timeline. `since` is unix seconds.
 *
 * Note: for a true streaming experience this should switch to WebSocket,
 * but for Phase 4 polling is fine and avoids the WS-relay complexity.
 */
export function useAuditTail(
  huntId: string | null,
  since: number = 0,
  refetchMs = 1500,
) {
  return useQuery<AuditQueryResponse | null>({
    queryKey: ["audit", huntId, since],
    queryFn: () =>
      huntId
        ? apiGet<AuditQueryResponse>(
            `/api/hack/audit?hunt_id=${encodeURIComponent(huntId)}&since=${since}&limit=1000`,
          )
        : Promise.resolve(null),
    enabled: !!huntId,
    refetchInterval: huntId ? refetchMs : false,
    staleTime: 500,
  });
}
