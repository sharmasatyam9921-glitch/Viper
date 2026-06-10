"use client";

import { useState, useEffect } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import { FolderKanban, Play } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";

interface ProjectInfo {
  target: string;
  domain: string;
  scope: string[];
  total_findings: number;
  total_sessions: number;
}
// Rows from GET /api/sessions/list — the evograph hunt history (distinct from
// the live-hunt Session state machine in lib/types.ts).
interface HistSession {
  id: number; target: string; tech_stack?: string;
  start_time?: string; end_time?: string;
  findings_count: number; total_reward?: number;
}
// One ReACT step from GET /api/sessions/:id → traces[].
interface Trace {
  id: number; step_num: number;
  thought?: string; action?: string; observation?: string;
  reward?: number; timestamp?: string;
}
interface SessionDetail extends HistSession { traces?: Trace[] }

// History rows carry no explicit state; derive one from the timestamps.
function statusOf(s: { start_time?: string; end_time?: string }): string {
  if (s.end_time) return "completed";
  if (s.start_time) return "running";
  return "pending";
}

function StatePill({ state }: { state: string }) {
  const map = {
    running:   { bg: "var(--brand-soft)",    fg: "var(--brand)" },
    completed: { bg: "var(--success-soft)",  fg: "var(--success)" },
    error:     { bg: "var(--critical-soft)", fg: "var(--critical)" },
    pending:   { bg: "var(--surface-2)",     fg: "var(--ink-3)" },
  };
  const t = map[(state ?? "").toLowerCase() as keyof typeof map] ?? map.pending;
  return (
    <span className="pill" style={{ background: t.bg, color: t.fg, textTransform: "capitalize" }}>
      {state}
    </span>
  );
}

export default function ProjectsPage() {
  // Backend wraps the response in {project: {...}}; unwrap defensively
  // so we accept both shapes.
  const { data: projectRaw } =
    useApi<ProjectInfo | { project: ProjectInfo }>("project-info", "/api/projects", 10000);
  const project: ProjectInfo | null =
    projectRaw && "project" in projectRaw
      ? (projectRaw.project as ProjectInfo)
      : (projectRaw as ProjectInfo | null);
  const { data: sessionsRaw, refetch } = useApi<
    HistSession[] | { sessions: HistSession[] }
  >("sessions", "/api/sessions/list", 5000);
  const sessions: HistSession[] = Array.isArray(sessionsRaw)
    ? sessionsRaw
    : (sessionsRaw?.sessions ?? []);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    if (selectedId == null) { setDetail(null); return; }
    apiGet<SessionDetail>(`/api/sessions/${selectedId}`).then((d) => d && setDetail(d));
  }, [selectedId]);

  const startScan = async () => {
    setStarting(true);
    await apiPost("/api/scan/start", {});
    setStarting(false);
    refetch();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Workspace"
        title="Project"
        subtitle="Active engagement — target, scope, sessions, findings."
        actions={
          <button onClick={startScan} disabled={starting} className="btn-primary">
            <Play size={13} fill="currentColor" />
            {starting ? "Starting" : "New scan"}
          </button>
        }
      />

      <Card>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
          <div>
            <div className="kicker">Target</div>
            <div
              className="display mt-1"
              style={{ fontSize: "1.125rem", color: "var(--brand)", fontFamily: "var(--font-geist-sans)" }}
            >
              {project?.target ?? "Not configured"}
            </div>
          </div>
          <div>
            <div className="kicker">Domain</div>
            <div
              className="mt-1 text-sm"
              style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}
            >
              {project?.domain ?? "—"}
            </div>
          </div>
          <div>
            <div className="kicker">Findings</div>
            <div className="display mt-1" style={{ fontSize: "1.5rem" }}>
              {project?.total_findings ?? 0}
            </div>
          </div>
          <div>
            <div className="kicker">Sessions</div>
            <div className="display mt-1" style={{ fontSize: "1.5rem" }}>
              {project?.total_sessions ?? sessions?.length ?? 0}
            </div>
          </div>
        </div>

        {(project?.scope?.length ?? 0) > 0 && (
          <div className="mt-5" style={{ borderTop: "1px solid var(--border-1)", paddingTop: 16 }}>
            <div className="kicker mb-2">Scope</div>
            <div className="flex flex-wrap gap-1.5">
              {project?.scope.map((s) => (
                <span key={s} className="pill" style={{ background: "var(--surface-2)", color: "var(--ink-2)", fontFamily: "var(--font-geist-mono)" }}>
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card padding="none" className="lg:col-span-1 overflow-hidden flex flex-col" style={{ maxHeight: 540 }}>
          <CardHeader title="Sessions" kicker={`${sessions?.length ?? 0} total`} />
          <div className="flex-1 overflow-y-auto">
            {(sessions ?? []).length === 0 ? (
              <div className="p-6 text-sm text-center" style={{ color: "var(--ink-3)" }}>
                No sessions yet
              </div>
            ) : (sessions ?? []).map((s) => (
              <button
                key={s.id}
                onClick={() => setSelectedId(s.id)}
                className="w-full text-left px-5 py-3 transition-colors"
                style={{
                  background: selectedId === s.id ? "var(--surface-2)" : "transparent",
                  borderBottom: "1px solid var(--border-1)",
                }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium" style={{ color: "var(--ink-1)" }}>
                    Session #{s.id}
                  </span>
                  <StatePill state={statusOf(s)} />
                </div>
                <div className="text-xs flex items-center gap-2" style={{ color: "var(--ink-3)" }}>
                  <span className="truncate" style={{ maxWidth: 130 }}>{s.tech_stack || s.target}</span>
                  <span>·</span>
                  <span>{s.findings_count} findings</span>
                  {typeof s.total_reward === "number" && (
                    <>
                      <span>·</span>
                      <span>rwd {s.total_reward.toFixed(0)}</span>
                    </>
                  )}
                </div>
              </button>
            ))}
          </div>
        </Card>

        <Card className="lg:col-span-2" padding="none">
          {!detail ? (
            <EmptyState
              title="Pick a session"
              hint="Select a session on the left to see findings and details."
              icon={<FolderKanban size={20} />}
            />
          ) : (
            <div>
              <div className="px-5 py-4" style={{ borderBottom: "1px solid var(--border-1)" }}>
                <div className="kicker">Session #{detail.id}</div>
                <div className="display mt-0.5" style={{ fontSize: "1.25rem", fontFamily: "var(--font-geist-mono)" }}>
                  {detail.target}
                </div>
                <div className="text-xs mt-1 flex items-center gap-2" style={{ color: "var(--ink-3)" }}>
                  {detail.tech_stack && (
                    <>
                      <span className="pill" style={{ background: "var(--brand-soft)", color: "var(--brand-ink)" }}>{detail.tech_stack}</span>
                      <span>·</span>
                    </>
                  )}
                  <span>{detail.findings_count} findings</span>
                  {typeof detail.total_reward === "number" && (
                    <>
                      <span>·</span>
                      <span>reward {detail.total_reward.toFixed(1)}</span>
                    </>
                  )}
                  <span>·</span>
                  <StatePill state={statusOf(detail)} />
                </div>
              </div>

              <div className="p-5">
                <div className="kicker mb-3">Reasoning trace</div>
                {!detail.traces || detail.traces.length === 0 ? (
                  <div className="text-sm" style={{ color: "var(--ink-3)" }}>
                    No reasoning trace recorded for this session.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {detail.traces.map((t) => (
                      <div key={t.id} className="p-3 rounded-lg" style={{ background: "var(--surface-2)" }}>
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="pill" style={{ background: "var(--surface-1)", color: "var(--ink-3)", fontFamily: "var(--font-geist-mono)", fontSize: 11 }}>
                            #{t.step_num}
                          </span>
                          {t.action && (
                            <span className="pill" style={{ background: "var(--brand-soft)", color: "var(--brand-ink)", fontFamily: "var(--font-geist-mono)" }}>
                              {t.action}
                            </span>
                          )}
                          {typeof t.reward === "number" && (
                            <span className="text-xs ml-auto" style={{ color: t.reward > 0 ? "var(--success)" : "var(--ink-3)", fontWeight: 600 }}>
                              {t.reward > 0 ? "+" : ""}{t.reward}
                            </span>
                          )}
                        </div>
                        {t.thought && <div className="text-sm" style={{ color: "var(--ink-1)" }}>{t.thought}</div>}
                        {t.observation && <div className="text-xs mt-1.5" style={{ color: "var(--ink-3)" }}>{t.observation}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
