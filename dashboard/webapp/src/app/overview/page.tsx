"use client";

import { useApi } from "@/hooks/useApi";
import type { Overview, RiskScore, Finding } from "@/lib/types";
import {
  PieChart, Pie, Cell, LineChart, Line, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { Target, AlertTriangle, ShieldCheck, Activity, Flame } from "lucide-react";

import { StatCard } from "@/components/ui/StatCard";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { ActivityStream } from "@/components/ui/ActivityStream";
import { HuntPanel } from "@/components/ui/HuntPanel";

const CHART_COLORS = {
  critical: "var(--critical)",
  high:     "var(--high)",
  medium:   "var(--medium)",
  low:      "var(--low)",
  info:     "var(--info)",
} as const;

function RiskBadge({ data }: { data: RiskScore | null }) {
  if (!data) return null;
  const tone =
    data.score >= 80 ? "critical"
    : data.score >= 50 ? "high"
    : data.score >= 25 ? "medium"
    : "success";
  return (
    <div
      className="card p-4 flex items-center gap-4"
      style={{ minWidth: 240 }}
    >
      <div className="flex flex-col">
        <div className="kicker">Risk score</div>
        <div className="flex items-baseline gap-2 mt-1">
          <div
            className="display"
            style={{
              fontSize: "2rem",
              color: `var(--${tone})`,
              lineHeight: 1,
            }}
          >
            {data.score}
          </div>
          <div
            className="text-sm uppercase tracking-wider"
            style={{ color: "var(--ink-3)" }}
          >
            {data.grade}
          </div>
        </div>
      </div>
      <div
        className="h-12 w-px"
        style={{ background: "var(--border-1)" }}
      />
      <div className="flex flex-col gap-1 text-xs">
        <div className="flex gap-2">
          <SeverityPill severity="critical" label={`${data.critical} crit`} />
          <SeverityPill severity="high" label={`${data.high} high`} />
        </div>
        <div style={{ color: "var(--ink-3)" }}>
          Trend: <span style={{ color: "var(--ink-2)" }}>{data.trend}</span>
        </div>
      </div>
    </div>
  );
}

/* ---------- helpers ---------- */
function buildSparkline(
  timeline: { date: string; count: number }[] | null | undefined,
): { x: string; y: number }[] {
  if (!timeline || timeline.length === 0) return [];
  return timeline.slice(-14).map((p) => ({ x: p.date, y: p.count }));
}

function deltaFor(
  timeline: { date: string; count: number }[] | null | undefined,
): { trend: "up" | "down" | "flat"; delta: string } {
  if (!timeline || timeline.length < 2) return { trend: "flat", delta: "—" };
  const tail = timeline.slice(-7);
  const head = timeline.slice(-14, -7);
  const tailSum = tail.reduce((s, p) => s + p.count, 0);
  const headSum = head.reduce((s, p) => s + p.count, 0) || 1;
  const pct = ((tailSum - headSum) / headSum) * 100;
  const trend = pct > 1 ? "up" : pct < -1 ? "down" : "flat";
  const delta = `${pct > 0 ? "+" : ""}${pct.toFixed(0)}%`;
  return { trend, delta };
}

/* ---------- page ---------- */
export default function OverviewPage() {
  const { data: ov } = useApi<Overview>("overview", "/api/overview", 5000);
  const { data: risk } = useApi<RiskScore>("risk-score", "/api/risk-score", 5000);
  const { data: severity } = useApi<{ severity: string; count: number }[]>(
    "by-severity", "/api/findings/by-severity", 5000);
  // Backend timeline entries are {day, severity, count}; aggregate by day.
  const { data: timelineRaw } = useApi<
    | { date: string; count: number }[]
    | { day: string; severity: string; count: number }[]
  >("timeline", "/api/findings/timeline", 5000);
  const timeline = (() => {
    if (!timelineRaw || timelineRaw.length === 0) return [];
    if ("date" in timelineRaw[0]) {
      return timelineRaw as { date: string; count: number }[];
    }
    const byDay: Record<string, number> = {};
    for (const r of timelineRaw as { day: string; count: number }[]) {
      byDay[r.day] = (byDay[r.day] || 0) + r.count;
    }
    return Object.entries(byDay)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, count]) => ({ date, count }));
  })();
  const { data: byType } = useApi<{ type: string; count: number }[]>(
    "by-type", "/api/findings/by-type", 5000);
  // Backend returns {findings: [...]} (FindingsPage shape); unwrap.
  const { data: recentRaw } = useApi<Finding[] | { findings: Finding[] }>(
    "recent-findings", "/api/findings?limit=8", 5000);
  const recent: Finding[] = Array.isArray(recentRaw)
    ? recentRaw
    : (recentRaw?.findings ?? []);

  const spark = buildSparkline(timeline);
  const { trend, delta } = deltaFor(timeline);

  return (
    <div className="space-y-6">
      {/* Title row */}
      <div className="flex items-end justify-between">
        <div>
          <div className="kicker">Welcome back</div>
          <h1
            className="display mt-1"
            style={{ fontSize: "2rem" }}
          >
            What VIPER found while you were away
          </h1>
        </div>
        <RiskBadge data={risk ?? null} />
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          label="Targets"
          value={ov?.targets ?? 0}
          accent="brand"
          icon={<Target size={14} />}
          spark={spark}
        />
        <StatCard
          label="Findings"
          value={ov?.findings ?? 0}
          delta={delta}
          trend={trend}
          accent="info"
          icon={<AlertTriangle size={14} />}
          spark={spark}
        />
        <StatCard
          label="Validated"
          value={ov?.validated ?? 0}
          hint={ov ? `${Math.round(((ov.validated || 0) / Math.max(ov.findings, 1)) * 100)}% of total` : ""}
          accent="success"
          icon={<ShieldCheck size={14} />}
        />
        <StatCard
          label="Critical"
          value={ov?.critical ?? 0}
          accent="critical"
          icon={<Flame size={14} />}
        />
        <StatCard
          label="Sessions run"
          value={ov?.live?.sessions_run ?? 0}
          hint={ov ? `${Math.floor((ov.live?.uptime_seconds || 0) / 60)} min uptime` : ""}
          accent="medium"
          icon={<Activity size={14} />}
        />
      </div>

      {/* Hunt panel + charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <HuntPanel />

        {/* Severity donut */}
        <div className="card p-5">
          <div className="flex items-baseline justify-between mb-2">
            <span className="kicker">Severity mix</span>
            <span className="text-xs" style={{ color: "var(--ink-3)" }}>
              All findings
            </span>
          </div>
          <ResponsiveContainer width="100%" height={196}>
            <PieChart>
              <Pie
                data={severity ?? []}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={78}
                paddingAngle={2}
                stroke="var(--surface-1)"
                strokeWidth={2}
              >
                {(severity ?? []).map((d) => (
                  <Cell
                    key={d.severity}
                    fill={CHART_COLORS[d.severity as keyof typeof CHART_COLORS] ?? "var(--info)"}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Findings timeline */}
        <div className="card p-5">
          <div className="flex items-baseline justify-between mb-2">
            <span className="kicker">Findings over time</span>
            <span className="text-xs" style={{ color: "var(--ink-3)" }}>
              Last 14 days
            </span>
          </div>
          <ResponsiveContainer width="100%" height={196}>
            <LineChart data={timeline ?? []}>
              <CartesianGrid stroke="var(--border-1)" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fill: "var(--ink-3)", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "var(--ink-3)", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                width={28}
              />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="count"
                stroke="var(--brand)"
                strokeWidth={2}
                dot={{ r: 2, fill: "var(--brand)" }}
                activeDot={{ r: 4 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top vuln types + Live activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="card p-5 lg:col-span-2">
          <div className="flex items-baseline justify-between mb-2">
            <span className="kicker">Top vulnerability types</span>
            <span className="text-xs" style={{ color: "var(--ink-3)" }}>
              Last {byType?.length ?? 0} categories
            </span>
          </div>
          <ResponsiveContainer width="100%" height={264}>
            <BarChart
              data={(byType ?? []).slice(0, 10)}
              layout="vertical"
              margin={{ top: 4, right: 16, bottom: 4, left: 0 }}
            >
              <CartesianGrid stroke="var(--border-1)" horizontal={false} />
              <XAxis
                type="number"
                tick={{ fill: "var(--ink-3)", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                dataKey="type"
                type="category"
                tick={{ fill: "var(--ink-2)", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                width={130}
              />
              <Tooltip cursor={{ fill: "var(--surface-2)" }} />
              <Bar
                dataKey="count"
                fill="var(--brand)"
                radius={[0, 6, 6, 0]}
                background={{ fill: "var(--surface-2)", radius: 6 }}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <ActivityStream limit={20} />
      </div>

      {/* Recent findings table */}
      <div className="card overflow-hidden">
        <div
          className="flex items-baseline justify-between px-5 py-4"
          style={{ borderBottom: "1px solid var(--border-1)" }}
        >
          <span className="kicker">Recent findings</span>
          <a
            href="/findings"
            className="text-xs"
            style={{ color: "var(--brand)" }}
          >
            View all →
          </a>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ color: "var(--ink-3)", textAlign: "left" }}>
              <th className="font-normal text-xs uppercase tracking-wider px-5 py-2">Severity</th>
              <th className="font-normal text-xs uppercase tracking-wider px-3 py-2">Title</th>
              <th className="font-normal text-xs uppercase tracking-wider px-3 py-2">Type</th>
              <th className="font-normal text-xs uppercase tracking-wider px-3 py-2">URL</th>
              <th className="font-normal text-xs uppercase tracking-wider px-3 py-2 text-right">Conf.</th>
            </tr>
          </thead>
          <tbody>
            {(recent ?? []).slice(0, 8).map((f) => (
              <tr
                key={f.id}
                className="transition-colors"
                style={{ borderTop: "1px solid var(--border-1)" }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "var(--surface-2)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                }}
              >
                <td className="px-5 py-3">
                  <SeverityPill severity={f.severity as never} />
                </td>
                <td className="px-3 py-3" style={{ color: "var(--ink-1)" }}>
                  {f.title}
                </td>
                <td className="px-3 py-3" style={{ color: "var(--ink-2)" }}>
                  <span
                    className="px-2 py-0.5 rounded text-xs"
                    style={{
                      background: "var(--surface-2)",
                      fontFamily: "var(--font-geist-mono)",
                    }}
                  >
                    {f.vuln_type}
                  </span>
                </td>
                <td
                  className="px-3 py-3 truncate max-w-md"
                  style={{
                    color: "var(--ink-2)",
                    fontFamily: "var(--font-geist-mono)",
                    fontSize: 12,
                  }}
                >
                  {f.url}
                </td>
                <td className="px-3 py-3 text-right" style={{ color: "var(--ink-2)" }}>
                  {(f.confidence * 100).toFixed(0)}%
                </td>
              </tr>
            ))}
            {(!recent || recent.length === 0) && (
              <tr>
                <td
                  colSpan={5}
                  className="px-5 py-6 text-center text-sm"
                  style={{ color: "var(--ink-3)" }}
                >
                  No findings yet — launch a hunt to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
