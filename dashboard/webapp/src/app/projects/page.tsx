"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import type { Session, Finding } from "@/lib/types";

interface ProjectInfo {
  target: string;
  domain: string;
  scope: string[];
  total_findings: number;
  total_sessions: number;
}

interface SessionDetail extends Session {
  findings?: Finding[];
}

/* ---------- phase badge ---------- */
const PHASE_STYLE: Record<string, string> = {
  recon: "bg-blue-500/20 text-blue-400",
  scan: "bg-cyan-500/20 text-cyan-400",
  exploit: "bg-orange-500/20 text-orange-400",
  report: "bg-emerald-500/20 text-emerald-400",
  complete: "bg-emerald-500/20 text-emerald-400",
  idle: "bg-zinc-600/20 text-zinc-400",
};

function PhaseBadge({ phase }: { phase: string }) {
  const p = phase.toLowerCase();
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${PHASE_STYLE[p] ?? PHASE_STYLE.idle}`}
    >
      {phase}
    </span>
  );
}

/* ---------- state badge ---------- */
function StateBadge({ state }: { state: string }) {
  const s = state.toLowerCase();
  const color =
    s === "running"
      ? "text-cyan-400"
      : s === "completed"
        ? "text-emerald-400"
        : s === "error"
          ? "text-red-400"
          : "text-zinc-400";
  return <span className={`text-xs font-semibold ${color}`}>{state}</span>;
}

/* ---------- page ---------- */
export default function ProjectsPage() {
  const { data: project } = useApi<ProjectInfo>(
    "project-info",
    "/api/project",
    10000,
  );
  const { data: sessions, refetch: refetchSessions } = useApi<Session[]>(
    "sessions",
    "/api/sessions/list",
    5000,
  );

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [starting, setStarting] = useState(false);

  /* load session detail */
  useEffect(() => {
    if (selectedId == null) {
      setDetail(null);
      return;
    }
    apiGet<SessionDetail>(`/api/sessions/${selectedId}`).then((d) => {
      if (d) setDetail(d);
    });
  }, [selectedId]);

  /* start new scan */
  const startScan = async () => {
    setStarting(true);
    await apiPost("/api/scan/start", {});
    setStarting(false);
    refetchSessions();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Project</h1>
        <button
          onClick={startScan}
          disabled={starting}
          className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 px-4 py-2 text-sm font-semibold text-white transition-colors"
        >
          {starting ? "Starting..." : "New Scan"}
        </button>
      </div>

      {/* project info card */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <div className="grid grid-cols-4 gap-6">
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Target
            </p>
            <p className="text-sm font-semibold text-cyan-400 mt-1">
              {project?.target ?? "Not configured"}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Domain
            </p>
            <p className="text-sm text-zinc-200 mt-1">
              {project?.domain ?? "-"}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Findings
            </p>
            <p className="text-sm font-bold text-zinc-200 mt-1">
              {project?.total_findings ?? 0}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Sessions
            </p>
            <p className="text-sm font-bold text-zinc-200 mt-1">
              {project?.total_sessions ?? sessions?.length ?? 0}
            </p>
          </div>
        </div>
      </div>

      {/* session list + detail */}
      <div className="grid grid-cols-2 gap-4">
        {/* list */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-4">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Scan History
          </h2>
          <div className="space-y-1 max-h-[60vh] overflow-y-auto">
            {(!sessions || sessions.length === 0) && (
              <p className="text-xs text-zinc-600">No sessions yet.</p>
            )}
            {(sessions ?? []).map((s) => (
              <button
                key={s.id}
                onClick={() => setSelectedId(s.id)}
                className={`w-full text-left rounded-lg px-3 py-2.5 transition-colors ${
                  selectedId === s.id
                    ? "bg-zinc-800 border border-zinc-700"
                    : "hover:bg-zinc-800/50 border border-transparent"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-200 truncate">
                    {s.target}
                  </span>
                  <StateBadge state={s.state} />
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <PhaseBadge phase={s.phase} />
                  <span className="text-[10px] text-zinc-500">
                    Iter {s.iteration} &middot; {s.findings_count} findings
                  </span>
                </div>
                <p className="text-[10px] text-zinc-600 mt-0.5">
                  {s.created_at}
                </p>
              </button>
            ))}
          </div>
        </div>

        {/* detail */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-4">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Session Detail
          </h2>
          {!detail ? (
            <p className="text-xs text-zinc-600">
              Select a session to view details.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase">State</p>
                  <StateBadge state={detail.state} />
                </div>
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase">Phase</p>
                  <PhaseBadge phase={detail.phase} />
                </div>
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase">
                    Iteration
                  </p>
                  <p className="text-sm text-zinc-200">{detail.iteration}</p>
                </div>
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase">
                    Findings
                  </p>
                  <p className="text-sm text-zinc-200">
                    {detail.findings_count}
                  </p>
                </div>
              </div>

              {/* session findings */}
              {detail.findings && detail.findings.length > 0 && (
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">
                    Findings
                  </p>
                  <div className="space-y-1 max-h-64 overflow-y-auto">
                    {detail.findings.map((f) => (
                      <div
                        key={f.id}
                        className="flex items-center gap-2 px-2 py-1.5 rounded bg-zinc-800/50 text-xs"
                      >
                        <span
                          className={`font-semibold ${
                            f.severity === "critical"
                              ? "text-red-400"
                              : f.severity === "high"
                                ? "text-orange-400"
                                : "text-zinc-400"
                          }`}
                        >
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="text-zinc-300 truncate">
                          {f.title}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
