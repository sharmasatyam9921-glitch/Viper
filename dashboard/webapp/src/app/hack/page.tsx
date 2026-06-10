"use client";

/**
 * /hack — live swarm-hunt dashboard. Picks up runs started via
 * `python viper.py hack <target>` or via the HuntPanel on /overview.
 */

import { useState, useMemo } from "react";
import { useHunts, useHuntSnapshot } from "@/hooks/useSwarm";
import { apiPost } from "@/lib/api";
import {
  HACK_PHASES,
  type HuntSummary,
  type HuntSnapshot,
  type PhaseStats,
  type WorkerSnapshot,
  type HuntFinding,
} from "@/lib/types";
import {
  Play, ShieldAlert, Activity, CheckCircle, FileText, AlertTriangle,
} from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityPill } from "@/components/ui/SeverityPill";

// ─── PhaseRibbon ────────────────────────────────────────────────────────

function PhaseRibbon({ phases }: { phases: PhaseStats[] }) {
  const byPhase = useMemo(
    () => Object.fromEntries(phases.map((p) => [p.phase, p])),
    [phases],
  );
  return (
    <div className="flex items-stretch gap-2">
      {HACK_PHASES.map((p, idx) => {
        const s = byPhase[p] as PhaseStats | undefined;
        const running = s && s.completed_at == null;
        const done = s && s.completed_at != null;
        const state = done ? "done" : running ? "running" : "pending";
        const tone =
          state === "done"
            ? { bg: "var(--success-soft)", fg: "var(--success)", border: "var(--success)" }
            : state === "running"
              ? { bg: "var(--brand-soft)", fg: "var(--brand)", border: "var(--brand)" }
              : { bg: "var(--surface-2)", fg: "var(--ink-3)", border: "var(--border-1)" };
        return (
          <div
            key={p}
            className="flex-1 rounded-lg px-4 py-3 transition-all"
            style={{
              background: tone.bg,
              border: `1px solid ${tone.border}`,
            }}
          >
            <div className="flex items-center gap-2">
              <span
                className={`relative w-1.5 h-1.5 rounded-full ${running ? "pulse-ring" : ""}`}
                style={{ background: tone.fg }}
              />
              <span className="kicker">{idx + 1}/{HACK_PHASES.length}</span>
              <span
                className="font-medium capitalize text-sm"
                style={{ color: tone.fg }}
              >
                {p}
              </span>
              {done && <CheckCircle size={11} style={{ color: tone.fg, marginLeft: "auto" }} />}
            </div>
            <div className="mt-1 text-xs" style={{ color: tone.fg, opacity: 0.85 }}>
              {!s ? (
                "pending"
              ) : (
                `${s.workers_completed}/${s.workers_dispatched} workers · ${s.findings_count} findings`
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── WorkerGrid ─────────────────────────────────────────────────────────

function WorkerGrid({ workers }: { workers: WorkerSnapshot[] }) {
  if (!workers.length) {
    return (
      <div className="text-sm py-4 px-2" style={{ color: "var(--ink-3)" }}>
        No workers yet.
      </div>
    );
  }
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2">
      {workers.map((w) => {
        const running = !w.outcome;
        const failed = w.outcome === "error";
        const dur = w.duration_ms != null ? `${(w.duration_ms / 1000).toFixed(1)}s` : "—";
        return (
          <div
            key={w.worker_id}
            className="rounded-lg p-2 transition-colors"
            style={{
              background: running
                ? "var(--brand-soft)"
                : failed
                  ? "var(--critical-soft)"
                  : "var(--success-soft)",
              border: "1px solid var(--border-1)",
            }}
          >
            <div className="flex items-center gap-2">
              <span
                className={`w-1.5 h-1.5 rounded-full ${running ? "pulse-ring" : ""}`}
                style={{
                  background: running
                    ? "var(--brand)"
                    : failed
                      ? "var(--critical)"
                      : "var(--success)",
                }}
              />
              <span
                className="text-xs font-medium truncate"
                style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}
                title={w.worker_id}
              >
                {w.worker_id.slice(0, 12)}
              </span>
            </div>
            <div className="mt-1 text-[10px] capitalize" style={{ color: "var(--ink-3)" }}>
              {w.phase} · {dur}
            </div>
            <div className="mt-0.5 text-[10px] truncate" style={{ color: "var(--ink-2)" }}>
              {w.last_action || "…"}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── FindingsStream ─────────────────────────────────────────────────────

function FindingsStream({ findings }: { findings: HuntFinding[] }) {
  if (!findings.length) {
    return (
      <div className="text-sm py-4 px-2" style={{ color: "var(--ink-3)" }}>
        Nothing found yet.
      </div>
    );
  }
  return (
    <div className="space-y-1.5 max-h-[420px] overflow-y-auto">
      {findings.map((f, i) => {
        const title =
          (typeof f.payload?.title === "string" && f.payload.title) ||
          (typeof f.payload?.vuln_type === "string" && f.payload.vuln_type) ||
          "Finding";
        const url = typeof f.payload?.url === "string" ? f.payload.url : null;
        return (
          <div
            key={i}
            className="flex items-center gap-3 p-2.5 rounded-lg fade-in"
            style={{ background: "var(--surface-2)" }}
          >
            <SeverityPill severity={f.severity as never} />
            <div className="flex-1 min-w-0">
              <div className="text-sm truncate" style={{ color: "var(--ink-1)" }}>
                {title}
              </div>
              {url && (
                <div
                  className="text-xs truncate mt-0.5"
                  style={{ color: "var(--ink-3)", fontFamily: "var(--font-geist-mono)" }}
                >
                  {url}
                </div>
              )}
            </div>
            <span
              className="pill"
              style={{ background: "var(--surface-1)", color: "var(--ink-2)" }}
            >
              {f.phase}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ─── HuntsList ──────────────────────────────────────────────────────────

function HuntsList({
  hunts, selectedId, onSelect,
}: {
  hunts: HuntSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (!hunts.length) {
    return (
      <div className="p-4 text-sm" style={{ color: "var(--ink-3)" }}>
        No hunts recorded yet. Run{" "}
        <code
          className="px-1.5 py-0.5 rounded text-xs"
          style={{
            background: "var(--surface-2)",
            fontFamily: "var(--font-geist-mono)",
          }}
        >
          python viper.py hack &lt;target&gt;
        </code>
        .
      </div>
    );
  }
  return (
    <div>
      {hunts.map((h) => {
        const active = h.hunt_id === selectedId;
        const ago = Math.max(0, Math.round(Date.now() / 1000 - h.last_event_at));
        const agoLabel =
          ago < 60 ? `${ago}s ago`
          : ago < 3600 ? `${Math.round(ago / 60)}m ago`
          : `${Math.round(ago / 3600)}h ago`;
        return (
          <button
            key={h.hunt_id}
            onClick={() => onSelect(h.hunt_id)}
            className="w-full text-left px-4 py-3 transition-colors"
            style={{
              background: active ? "var(--surface-2)" : "transparent",
              borderBottom: "1px solid var(--border-1)",
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <span
                className="text-xs font-medium truncate"
                style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}
              >
                {h.target ?? h.hunt_id}
              </span>
              <span className="text-[10px]" style={{ color: "var(--ink-3)" }}>{agoLabel}</span>
            </div>
            <div className="mt-1 text-[11px] flex gap-3" style={{ color: "var(--ink-3)" }}>
              <span>{h.event_count} events</span>
              <span>{h.finding_count} findings</span>
            </div>
          </button>
        );
      })}
    </div>
  );
}

// ─── NewHuntForm ────────────────────────────────────────────────────────

interface StartResp {
  ok: boolean;
  pid?: number;
  command_preview?: string;
  error?: string;
}

function NewHuntForm({ onStarted }: { onStarted: () => void }) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"" | "ctf" | "bugbounty" | "lab">("");
  const [go, setGo] = useState(false);
  const [timeMin, setTimeMin] = useState("");
  const [workers, setWorkers] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [last, setLast] = useState<StartResp | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) {
      setLast({ ok: false, error: "Target required" });
      return;
    }
    setSubmitting(true);
    setLast(null);
    const payload: Record<string, unknown> = { target: target.trim(), go };
    if (profile) payload.profile = profile;
    if (timeMin) payload.time = Number(timeMin);
    if (workers) payload.workers = Number(workers);
    const r = await apiPost<StartResp>("/api/hack/start", payload);
    setSubmitting(false);
    setLast(r ?? { ok: false, error: "Network error" });
    if (r?.ok) { setTarget(""); onStarted(); }
  }

  return (
    <Card>
      <form onSubmit={submit} className="space-y-3">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert size={14} style={{ color: "var(--brand)" }} />
          <span className="kicker">New hunt</span>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[260px]">
            <span className="kicker">Target</span>
            <input
              type="text"
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full mt-1 px-3 py-2 rounded-lg outline-none text-sm"
              style={{
                background: "var(--surface-2)",
                border: "1px solid var(--border-1)",
                color: "var(--ink-1)",
                fontFamily: "var(--font-geist-mono)",
              }}
            />
          </label>
          <label>
            <span className="kicker">Profile</span>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value as "" | "ctf" | "bugbounty" | "lab")}
              className="block mt-1 px-3 py-2 rounded-lg text-sm outline-none"
              style={{
                background: "var(--surface-2)",
                border: "1px solid var(--border-1)",
                color: "var(--ink-1)",
              }}
            >
              <option value="">auto</option>
              <option value="ctf">CTF</option>
              <option value="bugbounty">Bug Bounty</option>
              <option value="lab">Lab</option>
            </select>
          </label>
          <label>
            <span className="kicker">Time (min)</span>
            <input
              type="number"
              min="1"
              value={timeMin}
              onChange={(e) => setTimeMin(e.target.value)}
              className="block w-24 mt-1 px-3 py-2 rounded-lg text-sm outline-none"
              style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
            />
          </label>
          <label>
            <span className="kicker">Workers</span>
            <input
              type="number"
              min="1"
              value={workers}
              onChange={(e) => setWorkers(e.target.value)}
              className="block w-24 mt-1 px-3 py-2 rounded-lg text-sm outline-none"
              style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
            />
          </label>
          <label className="flex items-center gap-2 text-sm" style={{ color: "var(--ink-2)" }}>
            <input type="checkbox" checked={go} onChange={(e) => setGo(e.target.checked)} />
            --go (high concurrency)
          </label>
          <button type="submit" disabled={submitting} className="btn-primary">
            <Play size={13} fill="currentColor" />
            {submitting ? "Launching" : "Hunt"}
          </button>
        </div>
        {last && (
          <div
            className="text-xs px-3 py-2 rounded-lg fade-in"
            style={{
              background: last.ok ? "var(--success-soft)" : "var(--critical-soft)",
              color: last.ok ? "var(--success)" : "var(--critical)",
            }}
          >
            {last.ok ? (
              <>Launched (pid {last.pid}) · <code style={{ fontFamily: "var(--font-geist-mono)" }}>viper.py {last.command_preview}</code></>
            ) : (
              <>Error: {last.error}</>
            )}
          </div>
        )}
      </form>
    </Card>
  );
}

// ─── HuntStatusBanner ───────────────────────────────────────────────────
// Surfaces WHY a hunt stopped (status + reason) and the report link/button.
// Directly answers the operator question "it stopped — why, and where's the
// report?" that the bare phase ribbon never explained.

const STATUS_TONE = {
  completed: { bg: "var(--success-soft)", fg: "var(--success)", Icon: CheckCircle, label: "Completed" },
  error: { bg: "var(--critical-soft)", fg: "var(--critical)", Icon: ShieldAlert, label: "Error" },
  stalled: { bg: "var(--medium-soft)", fg: "var(--medium)", Icon: AlertTriangle, label: "Stalled" },
  running: { bg: "var(--brand-soft)", fg: "var(--brand)", Icon: Activity, label: "Running" },
} as const;

function fmtTs(t?: number | null): string | null {
  return t ? new Date(t * 1000).toLocaleString() : null;
}

function HuntStatusBanner({
  snapshot, onGenerate, generating,
}: {
  snapshot: HuntSnapshot;
  onGenerate: () => void;
  generating: boolean;
}) {
  const status = snapshot.status ?? "running";
  const tone = STATUS_TONE[status] ?? STATUS_TONE.running;
  const running = status === "running";
  const started = fmtTs(snapshot.started_at);
  const ended = fmtTs(snapshot.ended_at);
  return (
    <Card>
      <div className="flex items-center gap-3 flex-wrap">
        <span
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium"
          style={{ background: tone.bg, color: tone.fg }}
        >
          <tone.Icon size={14} className={running ? "pulse-ring" : ""} />
          {tone.label}
        </span>
        {snapshot.reason && (
          <span className="text-sm" style={{ color: "var(--ink-2)" }}>
            {snapshot.reason}
          </span>
        )}
        <div className="ml-auto flex items-center gap-3">
          {started && (
            <span className="text-xs" style={{ color: "var(--ink-3)" }}>
              {started}{ended ? ` → ${ended}` : ""}
            </span>
          )}
          {snapshot.report ? (
            <a
              href={`/api/reports/${snapshot.report}`}
              target="_blank"
              rel="noreferrer"
              className="btn-primary"
            >
              <FileText size={13} /> View report
            </a>
          ) : (
            <button onClick={onGenerate} disabled={generating} className="btn-ghost">
              <FileText size={13} />
              {generating ? "Generating…" : "Generate report"}
            </button>
          )}
        </div>
      </div>
    </Card>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────

export default function HackPage() {
  const huntsQuery = useHunts();
  const hunts = huntsQuery.data?.hunts ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const effectiveSelectedId = selectedId ?? hunts[0]?.hunt_id ?? null;
  const snapshotQuery = useHuntSnapshot(effectiveSelectedId);
  const snapshot = snapshotQuery.data;

  const [generating, setGenerating] = useState(false);
  async function generateReport() {
    if (!effectiveSelectedId) return;
    setGenerating(true);
    await apiPost("/api/hack/report", { hunt_id: effectiveSelectedId });
    setGenerating(false);
    // Re-poll the snapshot so the freshly written report link appears.
    snapshotQuery.refetch();
  }

  return (
    <div className="space-y-5">
      <PageHeader
        kicker="Live"
        title="Hunt"
        subtitle="Real-time swarm dashboard. Picks up runs from the CLI or HuntPanel."
        actions={
          <div className="text-xs flex items-center gap-2" style={{ color: "var(--ink-3)" }}>
            <Activity size={12} />
            {huntsQuery.isFetching ? "Refreshing…" : `${hunts.length} hunts`}
          </div>
        }
      />

      <NewHuntForm onStarted={() => huntsQuery.refetch()} />

      {snapshot?.found && (
        <HuntStatusBanner
          snapshot={snapshot}
          onGenerate={generateReport}
          generating={generating}
        />
      )}

      <PhaseRibbon phases={snapshot?.phases ?? []} />

      <div className="grid grid-cols-12 gap-4">
        <Card padding="none" className="col-span-12 lg:col-span-3 overflow-hidden flex flex-col" style={{ maxHeight: 620 }}>
          <CardHeader title="Hunts" kicker={`${hunts.length} recent`} />
          <div className="flex-1 overflow-y-auto">
            <HuntsList
              hunts={hunts}
              selectedId={effectiveSelectedId}
              onSelect={setSelectedId}
            />
          </div>
        </Card>

        <section className="col-span-12 lg:col-span-9 space-y-4">
          <Card padding="none">
            <CardHeader
              title="Workers"
              kicker={`${snapshot?.workers?.length ?? 0} total`}
            />
            <div className="p-4">
              <WorkerGrid workers={snapshot?.workers ?? []} />
            </div>
          </Card>

          <Card padding="none">
            <CardHeader
              title="Findings"
              kicker={`${snapshot?.findings?.length ?? 0} streamed`}
            />
            <div className="p-4">
              {(snapshot?.findings?.length ?? 0) === 0 ? (
                <EmptyState title="Waiting for findings" hint="The swarm will publish findings here in real time." />
              ) : (
                <FindingsStream findings={snapshot?.findings ?? []} />
              )}
            </div>
          </Card>
        </section>
      </div>
    </div>
  );
}
