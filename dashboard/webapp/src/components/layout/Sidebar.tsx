"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Bot, Network, AlertTriangle, Target, Radar,
  BarChart3, Terminal, MessageSquare, Wrench, FileText, FolderKanban,
  Settings, ShieldAlert,
} from "lucide-react";
import clsx from "clsx";

const ICONS = {
  LayoutDashboard, Bot, Network, AlertTriangle, Target, Radar,
  BarChart3, Terminal, MessageSquare, Wrench, FileText, FolderKanban,
  Settings, ShieldAlert,
} as const;
type IconName = keyof typeof ICONS;

type NavItem =
  | { kind: "link"; href: string; icon: IconName; label: string; live?: boolean }
  | { kind: "section"; label: string }
  | { kind: "divider" };

const NAV: NavItem[] = [
  { kind: "section", label: "Overview" },
  { kind: "link", href: "/overview", icon: "LayoutDashboard", label: "Dashboard" },
  { kind: "link", href: "/agents",   icon: "Bot",             label: "Agents", live: true },
  { kind: "link", href: "/hack",     icon: "ShieldAlert",     label: "Hunt", live: true },

  { kind: "section", label: "Discovery" },
  { kind: "link", href: "/recon",    icon: "Radar",           label: "Recon" },
  { kind: "link", href: "/targets",  icon: "Target",          label: "Targets" },
  { kind: "link", href: "/graph",    icon: "Network",         label: "Attack Graph" },

  { kind: "section", label: "Findings" },
  { kind: "link", href: "/findings", icon: "AlertTriangle",   label: "Findings" },
  { kind: "link", href: "/insights", icon: "BarChart3",       label: "Insights" },
  { kind: "link", href: "/reports",  icon: "FileText",        label: "Reports" },

  { kind: "section", label: "Workspace" },
  { kind: "link", href: "/terminal", icon: "Terminal",        label: "Terminal" },
  { kind: "link", href: "/chat",     icon: "MessageSquare",   label: "Chat" },
  { kind: "link", href: "/cypherfix",icon: "Wrench",          label: "CypherFix" },
  { kind: "link", href: "/projects", icon: "FolderKanban",    label: "Projects" },
  { kind: "divider" },
  { kind: "link", href: "/settings", icon: "Settings",        label: "Settings" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      className="fixed left-0 top-0 h-full w-60 flex flex-col z-50"
      style={{
        background: "var(--surface-1)",
        borderRight: "1px solid var(--border-1)",
      }}
    >
      {/* Logo */}
      <div
        className="px-5 py-5"
        style={{ borderBottom: "1px solid var(--border-1)" }}
      >
        <Link href="/overview" className="flex items-center gap-3 group">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center text-sm font-semibold transition-transform group-hover:scale-105"
            style={{
              background: "var(--brand)",
              color: "white",
              fontFamily: "var(--font-serif)",
            }}
          >
            V
          </div>
          <div className="leading-tight">
            <div className="text-sm font-medium" style={{ color: "var(--ink-1)" }}>
              VIPER
            </div>
            <div
              className="text-[10px] tracking-wider uppercase"
              style={{ color: "var(--ink-3)" }}
            >
              Hunting Engine
            </div>
          </div>
        </Link>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-3 overflow-y-auto">
        {NAV.map((item, i) => {
          if (item.kind === "divider") {
            return (
              <div
                key={`d${i}`}
                className="my-3"
                style={{ borderTop: "1px solid var(--border-1)" }}
              />
            );
          }
          if (item.kind === "section") {
            return (
              <div key={`s${i}`} className="kicker px-3 pt-4 pb-1">
                {item.label}
              </div>
            );
          }
          const Icon = ICONS[item.icon];
          const active = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-sm transition-all"
              )}
              style={{
                color: active ? "var(--brand-ink)" : "var(--ink-2)",
                background: active ? "var(--brand-soft)" : "transparent",
                fontWeight: active ? 500 : 400,
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "var(--surface-2)";
                  el.style.color = "var(--ink-1)";
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "transparent";
                  el.style.color = "var(--ink-2)";
                }
              }}
            >
              <Icon size={15} strokeWidth={1.6} />
              <span className="flex-1">{item.label}</span>
              {item.live && (
                <span
                  className="inline-block w-1.5 h-1.5 rounded-full pulse-ring"
                  style={{ background: "var(--success)" }}
                  aria-label="live"
                />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div
        className="px-5 py-3 text-[10px] flex items-center justify-between"
        style={{ borderTop: "1px solid var(--border-1)", color: "var(--ink-3)" }}
      >
        <span>VIPER 6.0</span>
        <span style={{ fontFamily: "var(--font-geist-mono)" }}>
          {new Date().getFullYear()}
        </span>
      </div>
    </aside>
  );
}
