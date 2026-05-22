"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import type { Finding, Severity } from "@/lib/types";

/* ---------- severity badge ---------- */
const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-600/20 text-zinc-400 border-zinc-500/30",
};

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${SEV_STYLE[s] ?? SEV_STYLE.info}`}
    >
      {severity}
    </span>
  );
}

/* ---------- status badge ---------- */
const STATUS_STYLE: Record<string, string> = {
  pending: "text-zinc-400",
  running: "text-cyan-400 animate-pulse",
  completed: "text-emerald-400",
  failed: "text-red-400",
};

/* ---------- triage finding type ---------- */
interface TriageFinding extends Finding {
  priority_score?: number;
}

interface FixStatus {
  finding_id: number;
  status: "pending" | "running" | "completed" | "failed";
  message?: string;
}

/* ---------- page ---------- */
export default function CypherFixPage() {
  const { data: findings } = useApi<TriageFinding[]>(
    "triage-findings",
    "/api/triage/findings",
    5000,
  );

  const [fixStatuses, setFixStatuses] = useState<Record<number, FixStatus>>({});
  const pollingRef = useRef<Set<number>>(new Set());

  /* start fix */
  const startFix = async (findingId: number) => {
    setFixStatuses((prev) => ({
      ...prev,
      [findingId]: { finding_id: findingId, status: "running" },
    }));

    const result = await apiPost<{ job_id: string }>("/api/codefix/run", {
      finding_id: findingId,
    });

    if (!result) {
      setFixStatuses((prev) => ({
        ...prev,
        [findingId]: { finding_id: findingId, status: "failed", message: "Failed to start" },
      }));
      return;
    }

    /* poll status */
    pollingRef.current.add(findingId);
    const poll = setInterval(async () => {
      const status = await apiGet<FixStatus>(`/api/codefix/status?finding_id=${findingId}`);
      if (status) {
        setFixStatuses((prev) => ({ ...prev, [findingId]: status }));
        if (status.status === "completed" || status.status === "failed") {
          clearInterval(poll);
          pollingRef.current.delete(findingId);
        }
      }
    }, 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">CypherFix</h1>
        <span className="text-xs text-zinc-500">
          {findings?.length ?? 0} findings for remediation
        </span>
      </div>

      {/* findings list */}
      <div className="space-y-2">
        {(!findings || findings.length === 0) && (
          <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-8 text-center">
            <p className="text-zinc-500 text-sm">No findings to triage.</p>
            <p className="text-zinc-600 text-xs mt-1">
              Run a scan to discover vulnerabilities.
            </p>
          </div>
        )}

        {(findings ?? []).map((f) => {
          const status = fixStatuses[f.id];
          return (
            <div
              key={f.id}
              className="rounded-xl bg-zinc-900 border border-zinc-800 p-4 flex items-center gap-4"
            >
              {/* severity */}
              <div className="shrink-0">
                <SeverityBadge severity={f.severity} />
              </div>

              {/* info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-zinc-200 truncate">
                    {f.title}
                  </span>
                  <span className="text-xs text-zinc-500">{f.vuln_type}</span>
                </div>
                <div className="text-xs text-zinc-500 mt-0.5 truncate">
                  {f.url}
                </div>
              </div>

              {/* priority score */}
              {f.priority_score != null && (
                <div className="shrink-0 text-right">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
                    Priority
                  </p>
                  <p className="text-sm font-bold text-cyan-400">
                    {f.priority_score}
                  </p>
                </div>
              )}

              {/* status / action */}
              <div className="shrink-0 w-28 text-right">
                {status ? (
                  <div>
                    <span
                      className={`text-xs font-semibold ${STATUS_STYLE[status.status] ?? "text-zinc-400"}`}
                    >
                      {status.status}
                    </span>
                    {status.message && (
                      <p className="text-[10px] text-zinc-500 mt-0.5 truncate">
                        {status.message}
                      </p>
                    )}
                  </div>
                ) : (
                  <button
                    onClick={() => startFix(f.id)}
                    className="rounded-md bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                  >
                    Fix
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
