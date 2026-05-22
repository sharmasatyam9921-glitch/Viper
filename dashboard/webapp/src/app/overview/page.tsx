"use client";

import { useApi } from "@/hooks/useApi";
import type { Overview, RiskScore, LogEntry } from "@/lib/types";
import { SEVERITY_COLORS, type Severity } from "@/lib/types";
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

/* ---------- stat card ---------- */
function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number | string;
  accent?: string;
}) {
  return (
    <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
      <p className="text-xs uppercase tracking-wider text-zinc-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${accent ?? "text-zinc-100"}`}>
        {value}
      </p>
    </div>
  );
}

/* ---------- risk badge ---------- */
function RiskBadge({ data }: { data: RiskScore | null }) {
  if (!data) return null;
  const color =
    data.score >= 80
      ? "text-red-400 border-red-500/40"
      : data.score >= 50
        ? "text-orange-400 border-orange-500/40"
        : "text-emerald-400 border-emerald-500/40";
  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-semibold ${color}`}
    >
      <span className="text-lg">{data.score}</span>
      <span className="uppercase tracking-wider text-[10px]">
        {data.grade}
      </span>
      <span className="text-zinc-500 text-xs">({data.trend})</span>
    </div>
  );
}

/* ---------- page ---------- */
export default function OverviewPage() {
  const { data: ov } = useApi<Overview>("overview", "/api/overview", 5000);
  const { data: risk } = useApi<RiskScore>(
    "risk-score",
    "/api/risk-score",
    5000,
  );
  const { data: severity } = useApi<{ severity: string; count: number }[]>(
    "by-severity",
    "/api/findings/by-severity",
    5000,
  );
  const { data: timeline } = useApi<{ date: string; count: number }[]>(
    "timeline",
    "/api/findings/timeline",
    5000,
  );
  const { data: byType } = useApi<{ type: string; count: number }[]>(
    "by-type",
    "/api/findings/by-type",
    5000,
  );
  const { data: logs } = useApi<LogEntry[]>(
    "logs",
    "/api/logs?limit=30",
    5000,
  );

  return (
    <div className="space-y-6">
      {/* header row */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Overview</h1>
        <RiskBadge data={risk ?? null} />
      </div>

      {/* stat cards */}
      <div className="grid grid-cols-5 gap-4">
        <StatCard label="Targets" value={ov?.targets ?? 0} />
        <StatCard label="Findings" value={ov?.findings ?? 0} />
        <StatCard
          label="Validated"
          value={ov?.validated ?? 0}
          accent="text-emerald-400"
        />
        <StatCard
          label="Critical"
          value={ov?.critical ?? 0}
          accent="text-red-400"
        />
        <StatCard
          label="High"
          value={ov?.high ?? 0}
          accent="text-orange-400"
        />
      </div>

      {/* charts row */}
      <div className="grid grid-cols-3 gap-4">
        {/* severity donut */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Severity Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severity ?? []}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={3}
              >
                {(severity ?? []).map((d) => (
                  <Cell
                    key={d.severity}
                    fill={
                      SEVERITY_COLORS[d.severity as Severity] ?? "#6b7280"
                    }
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                }}
                itemStyle={{ color: "#e4e4e7" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* findings timeline */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Findings Timeline
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={timeline ?? []}>
              <XAxis
                dataKey="date"
                tick={{ fill: "#71717a", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#71717a", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                width={30}
              />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                }}
                itemStyle={{ color: "#e4e4e7" }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#22d3ee"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* top vuln types */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Top Vulnerability Types
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={(byType ?? []).slice(0, 8)} layout="vertical">
              <XAxis
                type="number"
                tick={{ fill: "#71717a", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                dataKey="type"
                type="category"
                tick={{ fill: "#a1a1aa", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                width={100}
              />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                }}
                itemStyle={{ color: "#e4e4e7" }}
              />
              <Bar dataKey="count" fill="#22d3ee" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* activity log */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
          Live Activity
        </h2>
        <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-xs">
          {(logs ?? []).map((entry, i) => (
            <div key={i} className="flex gap-2 leading-5">
              <span className="text-zinc-600 shrink-0 w-16">
                {entry.time ?? ""}
              </span>
              <span
                className={
                  entry.level === "error"
                    ? "text-red-400"
                    : entry.level === "warn"
                      ? "text-yellow-400"
                      : "text-zinc-400"
                }
              >
                {entry.text}
              </span>
            </div>
          ))}
          {(!logs || logs.length === 0) && (
            <p className="text-zinc-600">No activity yet.</p>
          )}
        </div>
      </div>
    </div>
  );
}
