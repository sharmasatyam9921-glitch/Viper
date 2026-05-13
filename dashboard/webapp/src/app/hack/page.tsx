"use client";

/**
 * /hack — live swarm-hunt dashboard.
 *
 * Three panes:
 *   ┌────────────────────────────────────────────────────────────┐
 *   │   PHASE RIBBON  (recon → vuln → exploit → post → report)   │
 *   ├──────────────────────┬─────────────────────────────────────┤
 *   │  HUNTS LIST          │  HUNT DETAIL                        │
 *   │  (polls /hunts every │   - WorkerGrid                      │
 *   │   5s, click to       │   - FindingsStream                  │
 *   │   select)            │   - (polls /hunt every 1.5s)        │
 *   └──────────────────────┴─────────────────────────────────────┘
 *
 * Backed by the Phase 4 endpoints:
 *   GET /api/hack/hunts         → recent hunts list
 *   GET /api/hack/hunt?hunt_id  → phases + workers + findings snapshot
 *   GET /api/hack/audit         → (used by AuditTimeline — deferred)
 */

import { useState, useMemo } from "react";
import { useHunts, useHuntSnapshot } from "@/hooks/useSwarm";
import {
  HACK_PHASES,
  SEVERITY_COLORS,
  type HackPhase,
  type HuntSummary,
  type PhaseStats,
  type WorkerSnapshot,
  type HuntFinding,
  type Severity,
} from "@/lib/types";

// ────────────────────────────────────────────────────────────────────────
// PhaseRibbon
// ────────────────────────────────────────────────────────────────────────

function PhaseRibbon({ phases }: { phases: PhaseStats[] }) {
  const byPhase = useMemo(
    () => Object.fromEntries(phases.map((p) => [p.phase, p])),
    [phases],
  );

  return (
    <div className="flex items-stretch gap-2 mb-6">
      {HACK_PHASES.map((p, idx) => {
        const stats = byPhase[p];
        const running = stats && stats.completed_at == null;
        const done = stats && stats.completed_at != null;
        const pending = !stats;
        return (
          <div
            key={p}
            className={[
              "flex-1 rounded-lg border px-4 py-3 transition-colors",
              done
                ? "border-emerald-700/50 bg-emerald-900/30"
                : running
                  ? "border-blue-600/60 bg-blue-900/30 animate-pulse"
                  : "border-zinc-800 bg-zinc-900/50",
            ].join(" ")}
          >
            <div className="flex items-center gap-2">
              <span
                className={[
                  "h-2 w-2 rounded-full",
                  done
                    ? "bg-emerald-500"
                    : running
                      ? "bg-blue-500"
                      : "bg-zinc-700",
                ].join(" ")}
              />
              <span className="uppercase text-xs tracking-wider text-zinc-400">
                {idx + 1}/{HACK_PHASES.length}
              </span>
              <span className="font-semibold text-zinc-100 capitalize">{p}</span>
            </div>
            <div className="mt-1 text-xs text-zinc-500">
              {pending ? (
                <span>pending</span>
              ) : (
                <span>
                  {stats!.workers_completed}/{stats!.workers_dispatched} workers ·{" "}
                  {stats!.findings_count} findings
                </span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// WorkerGrid
// ────────────────────────────────────────────────────────────────────────

function WorkerCard({ w }: { w: WorkerSnapshot }) {
  const failed = w.last_action === "worker.failed" || w.outcome === "failure";
  const completed = w.last_action === "worker.completed" && !failed;
  const running = w.last_action === "worker.dispatched" && !completed;
  const color = failed
    ? "border-red-700/60 bg-red-900/20 text-red-200"
    : completed
      ? "border-emerald-700/40 bg-emerald-900/15 text-emerald-100"
      : running
        ? "border-blue-600/50 bg-blue-900/15 text-blue-100 animate-pulse"
        : "border-zinc-800 bg-zinc-900/50 text-zinc-300";
  const duration =
    w.duration_ms != null
      ? w.duration_ms < 1000
        ? `${w.duration_ms}ms`
        : `${(w.duration_ms / 1000).toFixed(1)}s`
      : "—";
  return (
    <div className={`rounded-md border px-3 py-2 text-xs ${color}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono truncate">{w.worker_id}</span>
        <span className="uppercase text-[9px] tracking-wider text-zinc-500">
          {w.phase}
        </span>
      </div>
      <div className="mt-1 flex items-center justify-between text-zinc-400">
        <span>{duration}</span>
        <span>
          {w.findings_count > 0 ? `${w.findings_count} findings` : "—"}
        </span>
      </div>
    </div>
  );
}

function WorkerGrid({ workers }: { workers: WorkerSnapshot[] }) {
  if (!workers.length) {
    return (
      <div className="text-zinc-500 text-sm italic py-4">No workers yet.</div>
    );
  }
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2">
      {workers.map((w) => (
        <WorkerCard key={w.worker_id} w={w} />
      ))}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// FindingsStream
// ────────────────────────────────────────────────────────────────────────

function severityChip(sev: string) {
  const s = (sev || "info") as Severity;
  const color = SEVERITY_COLORS[s] ?? SEVERITY_COLORS.info;
  return (
    <span
      className="inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
      style={{ color, borderColor: color, border: "1px solid" }}
    >
      {s}
    </span>
  );
}

function FindingsStream({ findings }: { findings: HuntFinding[] }) {
  if (!findings.length) {
    return (
      <div className="text-zinc-500 text-sm italic py-4">No findings yet.</div>
    );
  }
  // Newest first
  const ordered = [...findings].sort((a, b) => b.ts - a.ts);
  return (
    <div className="divide-y divide-zinc-800 max-h-[440px] overflow-y-auto">
      {ordered.map((f, i) => {
        const title = (f.payload?.title as string) ?? "(no title)";
        const technique = (f.payload?.technique as string) ?? "";
        const url = (f.payload?.url as string) ?? "";
        return (
          <div key={i} className="py-2 flex items-start gap-3">
            {severityChip(f.severity)}
            <div className="min-w-0 flex-1">
              <p className="text-sm text-zinc-100 truncate">{title}</p>
              <p className="text-xs text-zinc-500 truncate">
                <span className="text-zinc-400">{f.phase}</span>
                {technique ? <span> · via {technique}</span> : null}
                {url ? <span> · {url}</span> : null}
              </p>
            </div>
            <span className="text-[10px] text-zinc-600 whitespace-nowrap">
              {new Date(f.ts * 1000).toLocaleTimeString()}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// HuntsList
// ────────────────────────────────────────────────────────────────────────

function HuntsList({
  hunts,
  selectedId,
  onSelect,
}: {
  hunts: HuntSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (!hunts.length) {
    return (
      <div className="text-zinc-500 text-sm italic py-4 px-3">
        No hunts recorded yet. Run{" "}
        <code className="rounded bg-zinc-800 px-1 py-0.5 text-xs">
          python viper.py hack &lt;target&gt;
        </code>{" "}
        to create one.
      </div>
    );
  }
  return (
    <ul className="divide-y divide-zinc-800">
      {hunts.map((h) => {
        const active = h.hunt_id === selectedId;
        const ago = Math.max(0, Math.round(Date.now() / 1000 - h.last_event_at));
        const agoLabel =
          ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.round(ago / 60)}m ago` : `${Math.round(ago / 3600)}h ago`;
        return (
          <li key={h.hunt_id}>
            <button
              onClick={() => onSelect(h.hunt_id)}
              className={`w-full text-left px-3 py-2 hover:bg-zinc-800/60 transition-colors ${active ? "bg-zinc-800/80" : ""}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-zinc-100 truncate">
                  {h.target ?? h.hunt_id}
                </span>
                <span className="text-[10px] text-zinc-500 whitespace-nowrap">{agoLabel}</span>
              </div>
              <div className="mt-0.5 text-[11px] text-zinc-500 flex gap-3">
                <span>{h.event_count} events</span>
                <span>{h.finding_count} findings</span>
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Page
// ────────────────────────────────────────────────────────────────────────

export default function HackPage() {
  const huntsQuery = useHunts();
  const hunts = huntsQuery.data?.hunts ?? [];

  // Default selection: most recent hunt
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const effectiveSelectedId = selectedId ?? hunts[0]?.hunt_id ?? null;

  const snapshotQuery = useHuntSnapshot(effectiveSelectedId);
  const snapshot = snapshotQuery.data;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <header className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Hack</h1>
          <p className="text-sm text-zinc-500">
            Live swarm-hunt dashboard. Picks up runs started via{" "}
            <code className="rounded bg-zinc-800 px-1 py-0.5 text-xs">
              python viper.py hack
            </code>
            .
          </p>
        </div>
        <div className="text-xs text-zinc-500">
          {huntsQuery.isFetching ? "Refreshing…" : `${hunts.length} hunts`}
        </div>
      </header>

      <PhaseRibbon phases={snapshot?.phases ?? []} />

      <div className="grid grid-cols-12 gap-4">
        <aside className="col-span-12 lg:col-span-3 rounded-xl border border-zinc-800 bg-zinc-900/40">
          <header className="px-3 py-2 border-b border-zinc-800 text-xs uppercase tracking-wider text-zinc-500">
            Hunts
          </header>
          <HuntsList
            hunts={hunts}
            selectedId={effectiveSelectedId}
            onSelect={setSelectedId}
          />
        </aside>

        <section className="col-span-12 lg:col-span-9 space-y-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
            <header className="mb-3 flex items-center justify-between">
              <h2 className="font-semibold">Workers</h2>
              <span className="text-xs text-zinc-500">
                {snapshot?.workers?.length ?? 0} total
              </span>
            </header>
            <WorkerGrid workers={snapshot?.workers ?? []} />
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
            <header className="mb-3 flex items-center justify-between">
              <h2 className="font-semibold">Findings</h2>
              <span className="text-xs text-zinc-500">
                {snapshot?.findings?.length ?? 0} streamed
              </span>
            </header>
            <FindingsStream findings={snapshot?.findings ?? []} />
          </div>
        </section>
      </div>
    </div>
  );
}
