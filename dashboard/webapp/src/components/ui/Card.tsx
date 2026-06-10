"use client";

import { ReactNode, HTMLAttributes } from "react";
import clsx from "clsx";

export function Card({
  children, hover, padding = "md", className, ...rest
}: {
  children: ReactNode;
  hover?: boolean;
  padding?: "none" | "sm" | "md" | "lg";
} & HTMLAttributes<HTMLDivElement>) {
  const pad =
    padding === "none" ? "" :
    padding === "sm"   ? "p-3" :
    padding === "lg"   ? "p-6" :
    "p-5";
  return (
    <div
      className={clsx("card", hover && "card-hover", pad, className)}
      {...rest}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title, kicker, action,
}: { title: ReactNode; kicker?: string; action?: ReactNode }) {
  return (
    <div
      className="px-5 py-3 flex items-center justify-between"
      style={{ borderBottom: "1px solid var(--border-1)" }}
    >
      <div>
        {kicker && <div className="kicker">{kicker}</div>}
        <div
          className="text-sm font-medium mt-0.5"
          style={{ color: "var(--ink-1)" }}
        >
          {title}
        </div>
      </div>
      {action}
    </div>
  );
}
