"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import type { AttackStat, Session } from "@/lib/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  LineChart,
  Line,
} from "recharts";

/* ---------- chart tooltip style ---------- */
const TOOLTIP_STYLE = {
  contentStyle: {
    background: "#18181b",
    border: "1px solid #3f3f46",
    borderRadius: 8,
  },
  itemStyle: { color: "#e4e4e7" },
};

/* ---------- kill chain stage ---------- */
interface KillChainStage {
  stage: string;
  count: number;
  success_rate?: number;
}

/* ---------- evograph types ---------- */
interface EvoStats {
  total_episodes: number;
  q_table_size: number;
  avg_reward: number;
  best_reward: number;
  exploration_rate: number;
}

interface TechMapEntry {
  tech: string;
  attacks: number;
  success_rate: number;
}

/* ---------- stat card ---------- */
function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-4">
      <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
        {label}
      </p>
      <p className={`mt-1 text-xl font-bold ${accent ?? "text-zinc-100"}`}>
        {value}
      </p>
    </div>
  );
}

/* ---------- page ---------- */
export default function InsightsPage() {
  const { data: attackStats } = useApi<AttackStat[]>(
    "attack-stats",
    "/api/attacks/stats",
    10000,
  );
  const { data: killChain } = useApi<KillChainStage[]>(
    "kill-chain",
    "/api/attacks/kill-chain",
    10000,
  );
  const { data: evoStats } = useApi<EvoStats>(
    "evo-stats",
    "/api/evograph/stats",
    10000,
  );
  const { data: techMap } = useApi<TechMapEntry[]>(
    "tech-map",
    "/api/evograph/tech-map",
    10000,
  );
  const { data: sessions } = useApi<Session[]>(
    "sessions-insights",
    "/api/sessions/list",
    10000,
  );

  /* attack stats bar chart data */
  const barData = (attackStats ?? []).map((a) => ({
    name: a.attack_type,
    success: Math.round(a.success_rate * 100),
    total: a.total,
  }));

  /* kill chain radar data */
  const radarData = (killChain ?? []).map((k) => ({
    stage: k.stage,
    count: k.count,
    rate: Math.round((k.success_rate ?? 0) * 100),
  }));

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-zinc-100">Insights</h1>

      {/* EvoGraph stats */}
      {evoStats && (
        <div className="grid grid-cols-5 gap-4">
          <StatCard
            label="Episodes"
            value={evoStats.total_episodes}
            accent="text-cyan-400"
          />
          <StatCard
            label="Q-Table Size"
            value={evoStats.q_table_size}
          />
          <StatCard
            label="Avg Reward"
            value={evoStats.avg_reward.toFixed(2)}
            accent="text-emerald-400"
          />
          <StatCard
            label="Best Reward"
            value={evoStats.best_reward.toFixed(2)}
            accent="text-yellow-400"
          />
          <StatCard
            label="Exploration"
            value={`${Math.round(evoStats.exploration_rate * 100)}%`}
          />
        </div>
      )}

      {/* charts row */}
      <div className="grid grid-cols-2 gap-4">
        {/* attack success rates */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Attack Success Rates
          </h2>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={barData} layout="vertical">
                <XAxis
                  type="number"
                  tick={{ fill: "#71717a", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  domain={[0, 100]}
                  tickFormatter={(v) => `${v}%`}
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  tick={{ fill: "#a1a1aa", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  width={120}
                />
                <Tooltip {...TOOLTIP_STYLE} formatter={(v) => `${v}%`} />
                <Bar dataKey="success" fill="#22d3ee" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-zinc-600 py-12 text-center">
              No attack data yet.
            </p>
          )}
        </div>

        {/* kill chain radar */}
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Kill Chain Coverage
          </h2>
          {radarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
                <PolarGrid stroke="#3f3f46" />
                <PolarAngleAxis
                  dataKey="stage"
                  tick={{ fill: "#a1a1aa", fontSize: 10 }}
                />
                <PolarRadiusAxis
                  tick={{ fill: "#71717a", fontSize: 9 }}
                  axisLine={false}
                />
                <Radar
                  dataKey="count"
                  stroke="#22d3ee"
                  fill="#22d3ee"
                  fillOpacity={0.2}
                />
                <Tooltip {...TOOLTIP_STYLE} />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-zinc-600 py-12 text-center">
              No kill chain data yet.
            </p>
          )}
        </div>
      </div>

      {/* tech map table */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
          EvoGraph Technology Map
        </h2>
        {techMap && techMap.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-700">
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Technology
                  </th>
                  <th className="px-4 py-2 text-right text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Attacks
                  </th>
                  <th className="px-4 py-2 text-right text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Success Rate
                  </th>
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider w-48">
                    Bar
                  </th>
                </tr>
              </thead>
              <tbody>
                {techMap.map((t) => (
                  <tr
                    key={t.tech}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                  >
                    <td className="px-4 py-2 text-zinc-200 font-mono text-xs">
                      {t.tech}
                    </td>
                    <td className="px-4 py-2 text-right text-zinc-300">
                      {t.attacks}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <span
                        className={
                          t.success_rate >= 0.5
                            ? "text-emerald-400"
                            : t.success_rate >= 0.2
                              ? "text-yellow-400"
                              : "text-zinc-400"
                        }
                      >
                        {Math.round(t.success_rate * 100)}%
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <div className="w-full bg-zinc-800 rounded-full h-2">
                        <div
                          className="bg-cyan-500 h-2 rounded-full transition-all"
                          style={{
                            width: `${Math.round(t.success_rate * 100)}%`,
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-zinc-600 text-center py-6">
            No technology data yet. Run scans to build the map.
          </p>
        )}
      </div>

      {/* sessions summary */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
          Session Summary
        </h2>
        {sessions && sessions.length > 0 ? (
          <div className="overflow-x-auto max-h-64 overflow-y-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-700">
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    State
                  </th>
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Phase
                  </th>
                  <th className="px-4 py-2 text-right text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Iterations
                  </th>
                  <th className="px-4 py-2 text-right text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Findings
                  </th>
                  <th className="px-4 py-2 text-left text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
                    Date
                  </th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr
                    key={s.id}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                  >
                    <td className="px-4 py-2 text-cyan-400 font-mono text-xs truncate max-w-[200px]">
                      {s.target}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`text-xs font-semibold ${
                          s.state === "running"
                            ? "text-cyan-400"
                            : s.state === "completed"
                              ? "text-emerald-400"
                              : s.state === "error"
                                ? "text-red-400"
                                : "text-zinc-400"
                        }`}
                      >
                        {s.state}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-zinc-300">
                      {s.phase}
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-zinc-300">
                      {s.iteration}
                    </td>
                    <td className="px-4 py-2 text-right text-xs font-semibold text-zinc-200">
                      {s.findings_count}
                    </td>
                    <td className="px-4 py-2 text-xs text-zinc-500">
                      {s.created_at}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-zinc-600 text-center py-6">
            No sessions recorded yet.
          </p>
        )}
      </div>
    </div>
  );
}
