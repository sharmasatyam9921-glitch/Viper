"use client";

import { Search } from "lucide-react";

export function SearchInput({
  value, onChange, placeholder = "Search…", monospace,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  monospace?: boolean;
}) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-full transition-shadow"
      style={{
        background: "var(--surface-2)",
        border: "1px solid var(--border-1)",
        minWidth: 240,
      }}
    >
      <Search size={13} strokeWidth={1.7} style={{ color: "var(--ink-3)" }} />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="flex-1 bg-transparent outline-none text-sm"
        style={{
          color: "var(--ink-1)",
          fontFamily: monospace
            ? "var(--font-geist-mono)"
            : "inherit",
        }}
      />
      {value && (
        <button
          onClick={() => onChange("")}
          className="text-xs"
          style={{ color: "var(--ink-3)" }}
        >
          ×
        </button>
      )}
    </div>
  );
}
