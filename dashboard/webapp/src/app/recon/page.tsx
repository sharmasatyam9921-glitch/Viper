"use client";

import { useState } from "react";
import { useApi } from "@/hooks/useApi";
import { apiPost } from "@/lib/api";
import type { ReconJob, ParallelGroup } from "@/lib/types";

type ReconJobsResponse = { jobs: ReconJob[] };

/* ---------- OSINT source toggles ---------- */
const OSINT_SOURCES = [
  "urlscan",
  "whois",
  "shodan",
  "otx",
  "virustotal",
  "censys",
  "fofa",
  "netlas",
  "criminalip",
  "zoomeye",
] as const;

/* ---------- phase badge ---------- */
const PHASE_COLORS: Record<string, string> = {
  domain_discovery: "bg-purple-500/20 text-purple-400",
  passive_intel: "bg-blue-500/20 text-blue-400",
  port_scanning: "bg-cyan-500/20 text-cyan-400",
  http_probing: "bg-emerald-500/20 text-emerald-400",
  resource_enum: "bg-yellow-500/20 text-yellow-400",
  vuln_scanning: "bg-orange-500/20 text-orange-400",
  mitre_enrichment: "bg-red-500/20 text-red-400",
};

function PhaseBadge({
  phase,
  timing,
}: {
  phase: string;
  timing?: number;
}) {
  const cls = PHASE_COLORS[phase] ?? "bg-zinc-700/30 text-zinc-400";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider ${cls}`}
    >
      {phase.replace(/_/g, " ")}
      {timing != null && (
        <span className="text-zinc-500">{timing.toFixed(1)}s</span>
      )}
    </span>
  );
}

/* ---------- job status badge ---------- */
function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "completed"
      ? "bg-emerald-500/20 text-emerald-400"
      : status === "running"
        ? "bg-cyan-500/20 text-cyan-400 animate-pulse"
        : status === "error"
          ? "bg-red-500/20 text-red-400"
          : "bg-zinc-700/30 text-zinc-400";
  return (
    <span
      className={`inline-block rounded-full px-2.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider ${cls}`}
    >
      {status}
    </span>
  );
}

/* ---------- parallel group card ---------- */
function GroupCard({ group }: { group: ParallelGroup }) {
  return (
    <div className="rounded-lg bg-zinc-950 border border-zinc-800 p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-zinc-200">{group.name}</span>
        <span className="text-[10px] text-zinc-500">
          {group.duration_sec.toFixed(1)}s
        </span>
      </div>
      <div className="flex flex-wrap gap-1">
        {group.sources.map((s) => (
          <span
            key={s}
            className="rounded-full bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400"
          >
            {s}
          </span>
        ))}
      </div>
      <p className="text-[10px] text-zinc-600 mt-1">
        {group.tasks} tasks
      </p>
    </div>
  );
}

/* ---------- page ---------- */
export default function ReconPage() {
  const [target, setTarget] = useState("");
  const [sources, setSources] = useState<Set<string>>(
    new Set(OSINT_SOURCES),
  );
  const [masscanRate, setMasscanRate] = useState("1000");
  const [roeStart, setRoeStart] = useState("00:00");
  const [roeEnd, setRoeEnd] = useState("23:59");
  const [skipEmpty, setSkipEmpty] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);

  const { data: jobsResp, refetch } = useApi<ReconJobsResponse>(
    "recon-jobs",
    "/api/recon/pipeline/list",
    3000,
  );
  const jobs: ReconJob[] = jobsResp?.jobs ?? [];

  // Poll the full detail for the selected job (list response is trimmed).
  const { data: activeDetail } = useApi<ReconJob>(
    selectedJob ? `recon-job-${selectedJob}` : "recon-job-none",
    selectedJob ? `/api/recon/pipeline/${selectedJob}` : "",
    selectedJob ? 2000 : undefined,
  );

  const toggleSource = (s: string) => {
    setSources((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const startPipeline = async () => {
    if (!target.trim()) return;
    setLaunching(true);
    await apiPost("/api/recon/pipeline/start", {
      target: target.trim(),
      osint_sources: Array.from(sources),
      masscan_rate: parseInt(masscanRate, 10) || 1000,
      roe_window_start: roeStart || null,
      roe_window_end: roeEnd || null,
      skip_active_on_empty: skipEmpty,
    });
    setLaunching(false);
    refetch();
  };

  const active: ReconJob | null =
    activeDetail ?? jobs.find((j) => j.id === selectedJob) ?? null;

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-zinc-100">Recon Pipeline</h1>

      {/* launcher */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5 space-y-4">
        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Target domain (e.g. example.com)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
          <button
            onClick={startPipeline}
            disabled={launching || !target.trim()}
            className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-zinc-700 disabled:text-zinc-500 px-5 py-2 text-sm font-medium text-white transition-colors"
          >
            {launching ? "Starting..." : "Run Pipeline"}
          </button>
        </div>

        {/* OSINT toggles */}
        <div>
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2">
            OSINT Sources
          </p>
          <div className="flex flex-wrap gap-2">
            {OSINT_SOURCES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSource(s)}
                className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                  sources.has(s)
                    ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/40"
                    : "bg-zinc-800 text-zinc-500 border-zinc-700 hover:text-zinc-300"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* options row */}
        <div className="flex gap-4 items-end">
          <div>
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
              Masscan Rate
            </label>
            <input
              type="number"
              value={masscanRate}
              onChange={(e) => setMasscanRate(e.target.value)}
              className="w-28 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
              RoE Window Start
            </label>
            <input
              type="time"
              value={roeStart}
              onChange={(e) => setRoeStart(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
              RoE Window End
            </label>
            <input
              type="time"
              value={roeEnd}
              onChange={(e) => setRoeEnd(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={skipEmpty}
              onChange={(e) => setSkipEmpty(e.target.checked)}
              className="rounded border-zinc-600 bg-zinc-950 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-xs text-zinc-400">Skip empty phases</span>
          </label>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* job history */}
        <div className="col-span-1 rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Job History
          </h2>
          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {jobs.map((j) => (
              <div
                key={j.id}
                onClick={() => setSelectedJob(j.id)}
                className={`rounded-lg border p-3 cursor-pointer transition-colors ${
                  selectedJob === j.id
                    ? "bg-zinc-800 border-cyan-500/40"
                    : "bg-zinc-950 border-zinc-800 hover:border-zinc-600"
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-zinc-200 truncate">
                    {j.target}
                  </span>
                  <StatusBadge status={j.status} />
                </div>
                <p className="text-[10px] text-zinc-600">
                  {new Date(j.started_at * 1000).toLocaleString()}
                </p>
              </div>
            ))}
            {jobs.length === 0 && (
              <p className="text-xs text-zinc-600">No jobs yet.</p>
            )}
          </div>
        </div>

        {/* active job detail */}
        <div className="col-span-2 rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          {active ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-zinc-100">
                  {active.target}
                </h2>
                <StatusBadge status={active.status} />
              </div>

              {/* phase timing badges */}
              <div>
                <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2">
                  Phases
                </p>
                <div className="flex flex-wrap gap-2">
                  {(active.phases_done ?? []).map((ph) => (
                    <PhaseBadge
                      key={ph}
                      phase={ph}
                      timing={active.phase_timings?.[ph]}
                    />
                  ))}
                </div>
              </div>

              {/* parallel groups */}
              {(active.parallel_groups?.length ?? 0) > 0 && (
                <div>
                  <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2">
                    Parallel Groups
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {active.parallel_groups.map((g, i) => (
                      <GroupCard key={i} group={g} />
                    ))}
                  </div>
                </div>
              )}

              {/* summary stats */}
              {Object.keys(active.summary ?? {}).length > 0 && (
                <div>
                  <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2">
                    Summary
                  </p>
                  <div className="grid grid-cols-4 gap-2">
                    {Object.entries(active.summary ?? {}).map(([k, v]) => (
                      <div
                        key={k}
                        className="rounded-lg bg-zinc-950 border border-zinc-800 p-3 text-center"
                      >
                        <p className="text-[10px] text-zinc-500 truncate">
                          {k.replace(/_/g, " ")}
                        </p>
                        <p className="text-sm font-bold text-zinc-200 mt-0.5">
                          {typeof v === "boolean" ? (v ? "Yes" : "No") : v}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {active.error && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3">
                  <p className="text-xs text-red-400">{active.error}</p>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-zinc-600 text-sm">
              Select a job to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
