"use client";

import { useApi } from "@/hooks/useApi";
import type { AgentMonitor, ReACTStep } from "@/lib/types";
import { Bot, Cpu, Activity, Zap } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { ActivityStream } from "@/components/ui/ActivityStream";
import { EmptyState } from "@/components/ui/EmptyState";

const AGENT_TONE: Record<string, { fg: string; bg: string; label: string }> = {
  active:   { fg: "var(--success)",  bg: "var(--success-soft)",  label: "Active" },
  thinking: { fg: "var(--brand)",    bg: "var(--brand-soft)",    label: "Thinking" },
  idle:     { fg: "var(--ink-3)",    bg: "var(--surface-2)",     label: "Idle" },
  error:    { fg: "var(--critical)", bg: "var(--critical-soft)", label: "Error" },
};

function AgentStatusPill({ status }: { status: string }) {
  const t = AGENT_TONE[status] ?? AGENT_TONE.idle;
  return (
    <span
      className="pill"
      style={{ background: t.bg, color: t.fg }}
    >
      {status === "thinking" && (
        <span
          className="w-1.5 h-1.5 rounded-full pulse-ring"
          style={{ background: "currentColor" }}
        />
      )}
      {t.label}
    </span>
  );
}

function fmtUptime(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

export default function AgentsPage() {
  const { data: monitor } = useApi<AgentMonitor>(
    "agents-monitor", "/api/agents/monitor", 5000);
  const { data: react } = useApi<ReACTStep>(
    "react-current", "/api/react/current", 5000);

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Swarm"
        title="Agents"
        subtitle={
          monitor
            ? `${monitor.agents.length} agents · ${monitor.active_scans} active scan${monitor.active_scans === 1 ? "" : "s"}`
            : "Loading…"
        }
        actions={
          monitor && (
            <div className="flex items-center gap-3 text-xs" style={{ color: "var(--ink-3)" }}>
              <div className="flex items-center gap-1.5">
                <Activity size={12} />
                <span>Phase</span>
                <span
                  className="pill"
                  style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
                >
                  {monitor.current_phase || "idle"}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <Zap size={12} />
                <span>Bus</span>
                <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>
                  {monitor.bus_messages}
                </span>
              </div>
            </div>
          )
        }
      />

      {/* Agent cards */}
      {(monitor?.agents ?? []).length === 0 ? (
        <EmptyState
          title="No agents running"
          hint="Agents start when a hunt is launched."
          icon={<Bot size={20} />}
        />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {(monitor?.agents ?? []).map((a) => (
            <Card key={a.name} hover className="cursor-default">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{
                      background: "var(--brand-soft)",
                      color: "var(--brand)",
                    }}
                  >
                    <Bot size={15} />
                  </div>
                  <div
                    className="text-sm font-medium"
                    style={{ color: "var(--ink-1)" }}
                  >
                    {a.name}
                  </div>
                </div>
                <AgentStatusPill status={a.status} />
              </div>

              <div className="grid grid-cols-2 gap-2 mt-3 text-xs">
                <div>
                  <div className="kicker">Findings</div>
                  <div
                    className="display mt-0.5"
                    style={{ fontSize: "1.125rem", color: "var(--ink-1)" }}
                  >
                    {a.findings}
                  </div>
                </div>
                <div>
                  <div className="kicker">Uptime</div>
                  <div
                    className="display mt-0.5"
                    style={{ fontSize: "1.125rem", color: "var(--ink-1)" }}
                  >
                    {fmtUptime(a.uptime)}
                  </div>
                </div>
              </div>

              <div
                className="mt-3 pt-3 text-[10px] flex items-center justify-between"
                style={{ borderTop: "1px solid var(--border-1)", color: "var(--ink-3)" }}
              >
                <span className="flex items-center gap-1">
                  <Activity size={10} />
                  {a.activity_count} actions
                </span>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* ReACT step + Activity stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card padding="none" className="lg:col-span-2 overflow-hidden">
          <div
            className="px-5 py-3"
            style={{ borderBottom: "1px solid var(--border-1)" }}
          >
            <div className="kicker flex items-center gap-2">
              <Cpu size={12} />
              ReACT — current step
            </div>
            {react && (
              <div className="text-sm mt-1" style={{ color: "var(--ink-2)" }}>
                Step {react.step} of {react.total_steps} ·
                <span style={{ color: "var(--ink-1)", fontWeight: 600, marginLeft: 4 }}>
                  reward {typeof react.reward === "number" ? react.reward.toFixed(2) : "—"}
                </span>
              </div>
            )}
          </div>
          <div className="p-5 space-y-4">
            {!react ? (
              <div className="text-sm" style={{ color: "var(--ink-3)" }}>
                No active ReACT loop.
              </div>
            ) : (
              <>
                <ReactSection label="Think" text={react.think} />
                <ReactSection label="Action" text={react.action} mono />
                <ReactSection label="Observation" text={react.observation} />
                {react.deep_think && (
                  <ReactSection
                    label="Deep think"
                    text={react.deep_think}
                    accent
                  />
                )}
              </>
            )}
          </div>
        </Card>

        <ActivityStream limit={25} />
      </div>
    </div>
  );
}

function ReactSection({
  label, text, mono, accent,
}: { label: string; text: string; mono?: boolean; accent?: boolean }) {
  if (!text) return null;
  return (
    <div>
      <div className="kicker">{label}</div>
      <pre
        className="mt-1 p-3 rounded-lg text-xs whitespace-pre-wrap"
        style={{
          background: accent ? "var(--brand-soft)" : "var(--surface-2)",
          color: accent ? "var(--brand-ink)" : "var(--ink-1)",
          border: "1px solid var(--border-1)",
          fontFamily: mono ? "var(--font-geist-mono)" : undefined,
          maxHeight: 220,
          overflow: "auto",
        }}
      >
        {text}
      </pre>
    </div>
  );
}
