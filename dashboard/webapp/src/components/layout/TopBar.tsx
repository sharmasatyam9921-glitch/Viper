"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { Moon, Sun, Search } from "lucide-react";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useApi } from "@/hooks/useApi";

const PATH_LABELS: Record<string, string> = {
  overview: "Dashboard",
  agents: "Agents",
  hack: "Hunt",
  recon: "Recon",
  targets: "Targets",
  graph: "Attack Graph",
  findings: "Findings",
  insights: "Insights",
  reports: "Reports",
  terminal: "Terminal",
  chat: "Chat",
  cypherfix: "CypherFix",
  projects: "Projects",
  settings: "Settings",
};

export function TopBar() {
  const { connected, lastMessage } = useWebSocket();
  // The WebSocket is often blocked by Chromium's cross-port localhost policy,
  // so WS-connected alone is a poor liveness signal. Poll a cheap health
  // endpoint: if the API answers we're "Online" (polling) even without WS.
  const { data: health } = useApi<{ ok: boolean }>("health", "/api/health", 5000);
  const apiUp = Boolean(health?.ok);
  // Three states: Live (real-time WS), Online (API up, polling), Offline.
  const status = connected ? "Live" : apiUp ? "Online" : "Offline";
  const online = connected || apiUp;
  const pathname = usePathname();
  const seg = (pathname || "/").split("/").filter(Boolean)[0] || "overview";
  const label = PATH_LABELS[seg] ?? seg;

  const [theme, setTheme] = useState<"light" | "dark">("light");
  useEffect(() => {
    const t = document.documentElement.getAttribute("data-theme") as
      | "light" | "dark" | null;
    if (t) setTheme(t);
  }, []);
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("viper-theme", next);
    setTheme(next);
  };

  // Tick the activity indicator briefly each time a WS message arrives.
  const [pulse, setPulse] = useState(false);
  useEffect(() => {
    if (!lastMessage) return;
    setPulse(true);
    const t = setTimeout(() => setPulse(false), 400);
    return () => clearTimeout(t);
  }, [lastMessage]);

  return (
    <header
      className="fixed top-0 left-60 right-0 h-14 flex items-center justify-between px-6 z-40"
      style={{
        background: "color-mix(in oklab, var(--surface-0) 86%, transparent)",
        borderBottom: "1px solid var(--border-1)",
        backdropFilter: "blur(10px)",
      }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <span
          className="display"
          style={{ color: "var(--ink-1)", fontSize: "1.05rem" }}
        >
          {label}
        </span>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        {/* Search trigger (placeholder) */}
        <button
          className="btn-ghost"
          title="Search (⌘K)"
          aria-label="search"
        >
          <Search size={14} strokeWidth={1.7} />
          <span className="text-xs hidden md:inline" style={{ color: "var(--ink-3)" }}>
            Search
          </span>
          <kbd
            className="hidden md:inline-flex items-center justify-center text-[10px] px-1.5 py-0.5 rounded"
            style={{
              background: "var(--surface-2)",
              color: "var(--ink-3)",
              fontFamily: "var(--font-geist-mono)",
            }}
          >
            ⌘K
          </kbd>
        </button>

        {/* Connection indicator — Live (WS) / Online (polling) / Offline */}
        <div
          className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs"
          title={
            connected
              ? "Real-time stream connected"
              : apiUp
                ? "API reachable — polling (WebSocket blocked)"
                : "Backend unreachable"
          }
          style={{
            background: online ? "var(--success-soft)" : "var(--critical-soft)",
            color: online ? "var(--success)" : "var(--critical)",
          }}
        >
          <span className="relative flex items-center justify-center w-2 h-2">
            <span
              className="absolute inset-0 rounded-full"
              style={{
                background: "currentColor",
                opacity: pulse ? 1 : 0.85,
                transition: "transform 200ms ease",
                transform: pulse ? "scale(1.6)" : "scale(1)",
              }}
            />
          </span>
          <span style={{ fontWeight: 500 }}>{status}</span>
        </div>

        {/* Theme toggle */}
        <button
          className="btn-ghost"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "switch to light" : "switch to dark"}
        >
          {theme === "dark"
            ? <Sun size={15} strokeWidth={1.7} />
            : <Moon size={15} strokeWidth={1.7} />}
        </button>
      </div>
    </header>
  );
}
