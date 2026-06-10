"use client";

import { ReactNode } from "react";
import { ResponsiveContainer, LineChart, Line, Tooltip } from "recharts";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

export interface StatCardProps {
  label: string;
  value: number | string;
  hint?: string;
  trend?: "up" | "down" | "flat";
  delta?: string;            // e.g. "+12.4%" or "-3"
  spark?: { x: string | number; y: number }[];
  accent?: "brand" | "critical" | "high" | "medium" | "low" | "success" | "info";
  icon?: ReactNode;
}

const ACCENT_TO_VAR: Record<NonNullable<StatCardProps["accent"]>, string> = {
  brand: "var(--brand)",
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  success: "var(--success)",
  info: "var(--info)",
};

export function StatCard(props: StatCardProps) {
  const { label, value, hint, trend, delta, spark, accent = "info", icon } = props;
  const accentColor = ACCENT_TO_VAR[accent];

  return (
    <div
      className="card card-hover p-5 group cursor-default relative overflow-hidden"
      style={{ minHeight: 130 }}
    >
      <div className="flex items-start justify-between">
        <div className="kicker">{label}</div>
        {icon && (
          <div style={{ color: "var(--ink-3)" }} className="opacity-60">
            {icon}
          </div>
        )}
      </div>

      <div className="mt-2 flex items-baseline gap-2">
        <div
          className="display"
          style={{ fontSize: "1.875rem", color: "var(--ink-1)" }}
        >
          {value}
        </div>
        {delta && (
          <div
            className="flex items-center gap-0.5 text-xs"
            style={{
              color:
                trend === "up"
                  ? "var(--success)"
                  : trend === "down"
                    ? "var(--critical)"
                    : "var(--ink-3)",
            }}
          >
            {trend === "up" && <TrendingUp size={12} />}
            {trend === "down" && <TrendingDown size={12} />}
            {trend === "flat" && <Minus size={12} />}
            <span>{delta}</span>
          </div>
        )}
      </div>

      {hint && (
        <div className="mt-1 text-xs" style={{ color: "var(--ink-3)" }}>
          {hint}
        </div>
      )}

      {spark && spark.length > 1 && (
        <div className="absolute inset-x-0 bottom-0 h-10 opacity-60 pointer-events-none">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={spark} margin={{ top: 4, bottom: 0, left: 0, right: 0 }}>
              <Tooltip
                contentStyle={{ display: "none" }}
                cursor={false}
              />
              <Line
                type="monotone"
                dataKey="y"
                stroke={accentColor}
                strokeWidth={1.5}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
