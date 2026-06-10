"use client";

import { Severity } from "@/lib/types";

const STYLE: Record<
  Severity | "validated" | "default",
  { bg: string; fg: string; label: string }
> = {
  critical:  { bg: "var(--critical-soft)", fg: "var(--critical)", label: "Critical" },
  high:      { bg: "var(--high-soft)",     fg: "var(--high)",     label: "High" },
  medium:    { bg: "var(--medium-soft)",   fg: "var(--medium)",   label: "Medium" },
  low:       { bg: "var(--low-soft)",      fg: "var(--low)",      label: "Low" },
  info:      { bg: "var(--info-soft)",     fg: "var(--info)",     label: "Info" },
  validated: { bg: "var(--success-soft)",  fg: "var(--success)",  label: "Validated" },
  default:   { bg: "var(--surface-2)",     fg: "var(--ink-2)",    label: "—" },
};

export function SeverityPill({
  severity, label,
}: { severity: Severity | "validated" | string; label?: string }) {
  const style = STYLE[severity as keyof typeof STYLE] ?? STYLE.default;
  return (
    <span
      className="pill"
      style={{
        background: style.bg,
        color: style.fg,
        fontVariant: "small-caps",
        letterSpacing: "0.04em",
      }}
    >
      {label ?? style.label}
    </span>
  );
}
