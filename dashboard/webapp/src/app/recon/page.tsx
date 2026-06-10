"use client";

import { useState } from "react";
import { useApi } from "@/hooks/useApi";
import { apiPost } from "@/lib/api";
import type { ReconJob } from "@/lib/types";
import { Play, Radar, CheckCircle, AlertCircle, Clock } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";

type ReconJobsResponse = { jobs: ReconJob[] };

const OSINT_SOURCES = [
  "urlscan", "whois", "shodan", "otx", "virustotal",
  "censys", "fofa", "netlas", "criminalip", "zoomeye",
] as const;

const PHASE_LABELS: Record<string, string> = {
  domain_discovery: "Domain discovery",
  passive_intel:    "Passive intel",
  port_scanning:    "Port scanning",
  http_probing:     "HTTP probing",
  resource_enum:    "Resource enum",
  vuln_scanning:    "Vuln scanning",
  mitre_enrichment: "MITRE enrichment",
};

function PhasePill({ phase, timing }: { phase: string; timing?: number }) {
  return (
    <span
      className="pill"
      style={{
        background: "var(--brand-soft)",
        color: "var(--brand-ink)",
        fontFamily: "var(--font-geist-sans)",
      }}
    >
      {PHASE_LABELS[phase] ?? phase?.replace(/_/g, " ") ?? "—"}
      {timing != null && (
        <span style={{ opacity: 0.7, marginLeft: 4 }}>
          {timing.toFixed(1)}s
        </span>
      )}
    </span>
  );
}

function StatusPill({ status }: { status: string }) {
  const map = {
    completed: { bg: "var(--success-soft)", fg: "var(--success)", icon: <CheckCircle size={11} /> },
    running:   { bg: "var(--brand-soft)",   fg: "var(--brand)",   icon: <Clock size={11} /> },
    error:     { bg: "var(--critical-soft)",fg: "var(--critical)",icon: <AlertCircle size={11} /> },
    starting:  { bg: "var(--medium-soft)",  fg: "var(--medium)",  icon: <Clock size={11} /> },
    cancelled: { bg: "var(--info-soft)",    fg: "var(--info)",    icon: null },
  };
  const t = map[status as keyof typeof map] ?? map.cancelled;
  return (
    <span
      className="pill"
      style={{ background: t.bg, color: t.fg, textTransform: "capitalize" }}
    >
      {t.icon}
      {status}
    </span>
  );
}

export default function ReconPage() {
  const [target, setTarget] = useState("");
  const [sources, setSources] = useState<Set<string>>(new Set(OSINT_SOURCES));
  const [masscanRate, setMasscanRate] = useState("1000");
  const [skipEmpty, setSkipEmpty] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);

  const { data: jobsResp, refetch } = useApi<ReconJobsResponse>(
    "recon-jobs", "/api/recon/pipeline/list", 3000);
  const jobs: ReconJob[] = jobsResp?.jobs ?? [];

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
      skip_active_on_empty: skipEmpty,
    });
    setLaunching(false);
    refetch();
  };

  const active = activeDetail ?? jobs.find((j) => j.id === selectedJob) ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Discovery"
        title="Recon Pipeline"
        subtitle="Run the 7-phase recon — domain → port → HTTP → resource → vuln → MITRE."
      />

      {/* Launcher */}
      <Card>
        <div className="flex gap-2 items-center">
          <Radar size={16} style={{ color: "var(--brand)" }} />
          <input
            type="text"
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && startPipeline()}
            className="flex-1 px-3 py-2 rounded-lg outline-none text-sm"
            style={{
              background: "var(--surface-2)",
              border: "1px solid var(--border-1)",
              color: "var(--ink-1)",
              fontFamily: "var(--font-geist-mono)",
            }}
          />
          <button
            onClick={startPipeline}
            className="btn-primary"
            disabled={launching || !target.trim()}
          >
            <Play size={13} fill="currentColor" />
            {launching ? "Starting" : "Run"}
          </button>
        </div>

        <div className="mt-4">
          <div className="kicker mb-2">OSINT sources</div>
          <div className="flex flex-wrap gap-1.5">
            {OSINT_SOURCES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSource(s)}
                className="pill cursor-pointer"
                style={{
                  background: sources.has(s) ? "var(--brand-soft)" : "var(--surface-2)",
                  color:      sources.has(s) ? "var(--brand-ink)" : "var(--ink-2)",
                  fontWeight: sources.has(s) ? 500 : 400,
                }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <div className="kicker mb-1">Masscan rate</div>
            <input
              type="number"
              value={masscanRate}
              onChange={(e) => setMasscanRate(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg outline-none text-sm"
              style={{
                background: "var(--surface-2)",
                border: "1px solid var(--border-1)",
                color: "var(--ink-1)",
              }}
            />
          </div>
          <label className="flex items-center gap-2 text-sm pt-5" style={{ color: "var(--ink-2)" }}>
            <input
              type="checkbox"
              checked={skipEmpty}
              onChange={(e) => setSkipEmpty(e.target.checked)}
            />
            Skip active recon if passive returns nothing
          </label>
        </div>
      </Card>

      {/* Jobs list */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card padding="none" className="lg:col-span-1 overflow-hidden flex flex-col" style={{ maxHeight: 540 }}>
          <CardHeader title="Recent jobs" kicker={`${jobs.length} total`} />
          <div className="flex-1 overflow-y-auto">
            {jobs.length === 0 && (
              <div className="p-6 text-sm text-center" style={{ color: "var(--ink-3)" }}>
                No jobs yet
              </div>
            )}
            {jobs.map((j) => (
              <button
                key={j.id}
                onClick={() => setSelectedJob(j.id)}
                className="w-full text-left px-5 py-3 transition-colors"
                style={{
                  background: selectedJob === j.id ? "var(--surface-2)" : "transparent",
                  borderBottom: "1px solid var(--border-1)",
                }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm" style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}>
                    {j.target}
                  </span>
                  <StatusPill status={j.status} />
                </div>
                <div className="text-xs flex items-center gap-2" style={{ color: "var(--ink-3)" }}>
                  <span>{j.phases_done.length}/7 phases</span>
                  <span>·</span>
                  <span>{new Date(j.started_at * 1000).toLocaleTimeString()}</span>
                </div>
              </button>
            ))}
          </div>
        </Card>

        {/* Job detail */}
        <Card className="lg:col-span-2" padding="none">
          {!active ? (
            <EmptyState
              title="Pick a job"
              hint="Select a recon job on the left to see its phase timeline."
            />
          ) : (
            <div>
              <div className="px-5 py-4" style={{ borderBottom: "1px solid var(--border-1)" }}>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="kicker">Target</div>
                    <div
                      className="display mt-0.5"
                      style={{ fontSize: "1.25rem", fontFamily: "var(--font-geist-sans)" }}
                    >
                      {active.target}
                    </div>
                  </div>
                  <StatusPill status={active.status} />
                </div>
              </div>

              {/* Phase timings */}
              <div className="p-5 space-y-2">
                <div className="kicker">Phases completed</div>
                <div className="flex flex-wrap gap-1.5">
                  {active.phases_done.map((p) => (
                    <PhasePill key={p} phase={p} timing={active.phase_timings[p]} />
                  ))}
                </div>
              </div>

              {/* Summary */}
              {Object.keys(active.summary || {}).length > 0 && (
                <div className="p-5" style={{ borderTop: "1px solid var(--border-1)" }}>
                  <div className="kicker mb-2">Summary</div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {Object.entries(active.summary).map(([k, v]) => (
                      <div key={k}>
                        <div className="kicker">{k.replace(/_/g, " ")}</div>
                        <div
                          className="display mt-0.5"
                          style={{ fontSize: "1.125rem", color: "var(--ink-1)" }}
                        >
                          {String(v)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {active.error && (
                <div className="p-5" style={{ borderTop: "1px solid var(--border-1)" }}>
                  <div className="kicker mb-2" style={{ color: "var(--critical)" }}>Error</div>
                  <pre
                    className="text-xs p-3 rounded-lg whitespace-pre-wrap"
                    style={{
                      background: "var(--critical-soft)",
                      color: "var(--critical)",
                      fontFamily: "var(--font-geist-mono)",
                    }}
                  >
                    {active.error}
                  </pre>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
