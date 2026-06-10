"use client";

import { useApi } from "@/hooks/useApi";
import type { AttackStat } from "@/lib/types";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { TrendingUp, Brain, Crosshair, Target as TargetIcon } from "lucide-react";

interface KillChainStage {
  stage?: string;
  phase?: string;          // backend ships `phase`; alias to stage
  count?: number;
  total?: number;          // backend ships `total`
  success_rate?: number;
}
// Mirrors GET /api/evograph/stats — a summary of the cross-session memory DB.
interface EvoStats {
  available: boolean;
  session_count: number; pattern_count: number;
  edge_count: number; total_attacks: number;
}
interface TechMapEntry { tech: string; attacks: number; success_rate: number }
// GET /api/sessions/list rows (distinct from the shared Session type, which
// describes the live-hunt state machine, not the evograph history table).
interface InsightSession {
  id: number; target: string; tech_stack?: string;
  start_time?: string; end_time?: string;
  findings_count: number; total_reward?: number;
}

export default function InsightsPage() {
  const { data: attackStats } = useApi<AttackStat[]>("attack-stats", "/api/attacks/stats", 10000);
  const { data: killChain } = useApi<KillChainStage[]>("kill-chain", "/api/attacks/kill-chain", 10000);
  const { data: evoStats } = useApi<EvoStats>("evo-stats", "/api/evograph/stats", 10000);
  const { data: techMap } = useApi<TechMapEntry[]>("tech-map", "/api/evograph/tech-map", 10000);
  const { data: sessionsRaw } = useApi<
    InsightSession[] | { sessions: InsightSession[] }
  >("sessions-insights", "/api/sessions/list", 10000);
  const sessions: InsightSession[] = Array.isArray(sessionsRaw)
    ? sessionsRaw
    : (sessionsRaw?.sessions ?? []);

  // Backend returns success_rate already as a percentage (0-100), not 0-1.
  // Guard against either shape so we don't render 2130%.
  const barData = (attackStats ?? []).slice(0, 10).map((a) => ({
    name: a.attack_type,
    success: Math.round(a.success_rate <= 1 ? a.success_rate * 100 : a.success_rate),
    total: a.total,
  }));

  const radarData = (killChain ?? []).map((k) => {
    const r = k.success_rate ?? 0;
    return {
      stage: k.stage ?? k.phase ?? "—",
      rate: Math.round(r <= 1 ? r * 100 : r),
    };
  });

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Analytics"
        title="Insights"
        subtitle="Q-learning telemetry, kill-chain efficiency, attack-stack patterns."
      />

      {/* EvoGraph stats — cross-session memory summary */}
      {evoStats?.available && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Sessions"
            value={evoStats.session_count}
            accent="brand"
            icon={<Brain size={14} />}
            hint="hunts recorded"
          />
          <StatCard
            label="Patterns learned"
            value={evoStats.pattern_count}
            accent="info"
          />
          <StatCard
            label="Graph edges"
            value={evoStats.edge_count}
            accent="medium"
            icon={<TrendingUp size={14} />}
          />
          <StatCard
            label="Total attacks"
            value={evoStats.total_attacks}
            accent="success"
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Attack success rates */}
        <Card padding="none">
          <CardHeader title="Attack success rate" kicker="By technique" />
          <div className="p-5">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={barData} layout="vertical" margin={{ left: 0, right: 16 }}>
                <CartesianGrid stroke="var(--border-1)" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`}
                       tick={{ fill: "var(--ink-3)", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis dataKey="name" type="category" width={120}
                       tick={{ fill: "var(--ink-2)", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="success" fill="var(--brand)" radius={[0, 6, 6, 0]}
                     background={{ fill: "var(--surface-2)", radius: 6 }} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Kill chain radar */}
        <Card padding="none">
          <CardHeader title="Kill chain efficiency" kicker="Reach per stage" />
          <div className="p-5">
            <ResponsiveContainer width="100%" height={280}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="var(--border-1)" />
                <PolarAngleAxis dataKey="stage" tick={{ fill: "var(--ink-2)", fontSize: 11 }} />
                <PolarRadiusAxis tick={{ fill: "var(--ink-3)", fontSize: 9 }} angle={90} />
                <Tooltip />
                <Radar dataKey="rate" stroke="var(--brand)" fill="var(--brand)" fillOpacity={0.22} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Tech stack map */}
      <Card padding="none">
        <CardHeader title="Tech stack success map" kicker="Which stacks bleed" />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ color: "var(--ink-3)", textAlign: "left" }}>
                {["Tech", "Attacks", "Success rate", ""].map((h, i) => (
                  <th key={i} className="font-normal text-xs uppercase tracking-wider px-5 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(techMap ?? []).slice(0, 14).map((t) => {
                const pct = Math.round(
                  t.success_rate <= 1 ? t.success_rate * 100 : t.success_rate,
                );
                return (
                  <tr key={t.tech} style={{ borderTop: "1px solid var(--border-1)" }}>
                    <td className="px-5 py-3" style={{ color: "var(--ink-1)" }}>
                      <span className="flex items-center gap-2">
                        <TargetIcon size={12} style={{ color: "var(--ink-3)" }} />
                        {t.tech}
                      </span>
                    </td>
                    <td className="px-5 py-3" style={{ color: "var(--ink-2)" }}>
                      {t.attacks}
                    </td>
                    <td className="px-5 py-3" style={{ color: "var(--ink-1)", fontWeight: 600 }}>
                      {pct}%
                    </td>
                    <td className="px-5 py-3 w-1/3">
                      <div
                        className="h-1.5 rounded-full overflow-hidden"
                        style={{ background: "var(--surface-2)" }}
                      >
                        <div
                          className="h-full transition-all"
                          style={{
                            width: `${pct}%`,
                            background: pct >= 60 ? "var(--success)"
                                         : pct >= 30 ? "var(--brand)"
                                         : "var(--ink-3)",
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
              {(!techMap || techMap.length === 0) && (
                <tr><td colSpan={4} className="px-5 py-6 text-center text-sm" style={{ color: "var(--ink-3)" }}>
                  No tech-map data yet
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Recent sessions */}
      <Card padding="none">
        <CardHeader title="Recent sessions" kicker={`${sessions?.length ?? 0} runs`} />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ color: "var(--ink-3)", textAlign: "left" }}>
                {["Target", "Tech stack", "Findings", "Reward", "Started"].map((h) => (
                  <th key={h} className="font-normal text-xs uppercase tracking-wider px-5 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(sessions ?? []).slice(0, 10).map((s) => (
                <tr key={s.id} style={{ borderTop: "1px solid var(--border-1)" }}>
                  <td className="px-5 py-3" style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)", fontSize: 12 }}>
                    {s.target}
                  </td>
                  <td className="px-5 py-3">
                    {s.tech_stack
                      ? <span className="pill" style={{ background: "var(--brand-soft)", color: "var(--brand-ink)" }}>
                          {s.tech_stack}
                        </span>
                      : <span style={{ color: "var(--ink-3)" }}>—</span>}
                  </td>
                  <td className="px-5 py-3" style={{ color: "var(--ink-1)", fontWeight: 600 }}>{s.findings_count}</td>
                  <td className="px-5 py-3" style={{ color: "var(--ink-2)" }}>
                    {typeof s.total_reward === "number" ? s.total_reward.toFixed(1) : "—"}
                  </td>
                  <td className="px-5 py-3" style={{ color: "var(--ink-3)", fontSize: 12 }}>
                    {s.start_time ? new Date(s.start_time).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
              {(!sessions || sessions.length === 0) && (
                <tr><td colSpan={5} className="px-5 py-6 text-center text-sm" style={{ color: "var(--ink-3)" }}>
                  No sessions yet
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
