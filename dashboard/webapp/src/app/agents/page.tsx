"use client";

import { useApi } from "@/hooks/useApi";
import type { AgentMonitor, ReACTStep } from "@/lib/types";

/* ---------- agent status badge ---------- */
function AgentStatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"
      ? "bg-emerald-500/20 text-emerald-400"
      : status === "thinking"
        ? "bg-cyan-500/20 text-cyan-400 animate-pulse"
        : status === "idle"
          ? "bg-zinc-700/30 text-zinc-400"
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

/* ---------- agent card ---------- */
function AgentCard({
  name,
  status,
  findings,
  uptime,
  activityCount,
}: {
  name: string;
  status: string;
  findings: number;
  uptime: number;
  activityCount: number;
}) {
  const hours = Math.floor(uptime / 3600);
  const mins = Math.floor((uptime % 3600) / 60);
  const uptimeStr =
    hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;

  return (
    <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-zinc-100">{name}</h3>
        <AgentStatusBadge status={status} />
      </div>
      <div className="grid grid-cols-3 gap-3 text-center">
        <div>
          <p className="text-lg font-bold text-zinc-100">{findings}</p>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
            Findings
          </p>
        </div>
        <div>
          <p className="text-lg font-bold text-zinc-100">{activityCount}</p>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
            Actions
          </p>
        </div>
        <div>
          <p className="text-lg font-bold text-zinc-100">{uptimeStr}</p>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
            Uptime
          </p>
        </div>
      </div>
    </div>
  );
}

/* ---------- ReACT step display ---------- */
function ReACTDisplay({ step }: { step: ReACTStep | null }) {
  if (!step) {
    return (
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
          ReACT Engine
        </h2>
        <p className="text-sm text-zinc-600">No active ReACT session.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500">
          ReACT Engine
        </h2>
        <div className="flex items-center gap-3 text-xs text-zinc-500">
          <span>
            Step{" "}
            <strong className="text-zinc-200">
              {step.step}/{step.total_steps}
            </strong>
          </span>
          <span>
            Reward{" "}
            <strong className="text-cyan-400">
              {step.reward.toFixed(2)}
            </strong>
          </span>
          <span>
            Q-table{" "}
            <strong className="text-zinc-200">{step.q_table_size}</strong>
          </span>
        </div>
      </div>

      {/* progress bar */}
      <div className="w-full h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all"
          style={{
            width: `${step.total_steps > 0 ? (step.step / step.total_steps) * 100 : 0}%`,
          }}
        />
      </div>

      {/* think / action / observation */}
      <div className="grid grid-cols-3 gap-4">
        <StepBlock label="Think" content={step.think} color="text-cyan-400" />
        <StepBlock
          label="Action"
          content={step.action}
          color="text-emerald-400"
        />
        <StepBlock
          label="Observation"
          content={step.observation}
          color="text-yellow-400"
        />
      </div>

      {/* deep think */}
      {step.deep_think && (
        <div>
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-1">
            Deep Think
          </p>
          <div className="rounded-lg bg-zinc-950 border border-zinc-800 p-3">
            <p className="text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed">
              {step.deep_think}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function StepBlock({
  label,
  content,
  color,
}: {
  label: string;
  content: string;
  color: string;
}) {
  return (
    <div>
      <p className={`text-[10px] uppercase tracking-wider mb-1 ${color}`}>
        {label}
      </p>
      <div className="rounded-lg bg-zinc-950 border border-zinc-800 p-3 min-h-[80px]">
        <p className="text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed">
          {content || "-"}
        </p>
      </div>
    </div>
  );
}

/* ---------- page ---------- */
export default function AgentsPage() {
  const { data: monitor } = useApi<AgentMonitor>(
    "agents-monitor",
    "/api/agents/monitor",
    5000,
  );
  const { data: react } = useApi<ReACTStep>(
    "react-current",
    "/api/react/current",
    5000,
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Agents</h1>
        {monitor && (
          <div className="flex gap-4 text-xs text-zinc-500">
            <span>
              Phase:{" "}
              <strong className="text-zinc-200">
                {monitor.current_phase || "idle"}
              </strong>
            </span>
            <span>
              Target:{" "}
              <strong className="text-zinc-200">
                {monitor.current_target || "none"}
              </strong>
            </span>
            <span>
              Bus msgs:{" "}
              <strong className="text-zinc-200">
                {monitor.bus_messages}
              </strong>
            </span>
            <span>
              Active scans:{" "}
              <strong className="text-zinc-200">
                {monitor.active_scans}
              </strong>
            </span>
          </div>
        )}
      </div>

      {/* agent cards grid */}
      <div className="grid grid-cols-4 gap-4">
        {(monitor?.agents ?? []).map((a) => (
          <AgentCard
            key={a.name}
            name={a.name}
            status={a.status}
            findings={a.findings}
            uptime={a.uptime}
            activityCount={a.activity_count}
          />
        ))}
        {(!monitor || monitor.agents.length === 0) && (
          <p className="col-span-4 text-center text-zinc-600 py-12">
            No agents registered. Start a hunt to activate agents.
          </p>
        )}
      </div>

      {/* ReACT engine */}
      <ReACTDisplay step={react ?? null} />
    </div>
  );
}
