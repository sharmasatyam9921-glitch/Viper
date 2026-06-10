"use client";

import { ReactNode } from "react";

export function PageHeader({
  title, kicker, subtitle, actions,
}: {
  title: string;
  kicker?: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-end justify-between flex-wrap gap-4 mb-6">
      <div>
        {kicker && <div className="kicker">{kicker}</div>}
        <h1
          className="display mt-1"
          style={{ fontSize: "1.875rem", lineHeight: 1.15 }}
        >
          {title}
        </h1>
        {subtitle && (
          <p
            className="mt-1 text-sm max-w-2xl"
            style={{ color: "var(--ink-3)" }}
          >
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
