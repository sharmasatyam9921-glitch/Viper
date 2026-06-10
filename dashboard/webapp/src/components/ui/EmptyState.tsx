"use client";

import { ReactNode } from "react";

export function EmptyState({
  title, hint, icon, action,
}: {
  title: string;
  hint?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="card p-10 text-center">
      {icon && (
        <div
          className="mx-auto mb-3 w-12 h-12 rounded-full flex items-center justify-center"
          style={{ background: "var(--surface-2)", color: "var(--ink-3)" }}
        >
          {icon}
        </div>
      )}
      <div
        className="display"
        style={{ fontSize: "1.125rem", color: "var(--ink-2)" }}
      >
        {title}
      </div>
      {hint && (
        <div
          className="mt-1 text-sm max-w-md mx-auto"
          style={{ color: "var(--ink-3)" }}
        >
          {hint}
        </div>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
