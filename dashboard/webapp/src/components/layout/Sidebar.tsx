"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Bot, Network, AlertTriangle, Target, Radar,
  BarChart3, Terminal, MessageSquare, Wrench, FileText, FolderKanban,
  Settings,
} from "lucide-react";
import clsx from "clsx";

const ICONS: Record<string, React.ComponentType<{ size?: number }>> = {
  LayoutDashboard, Bot, Network, AlertTriangle, Target, Radar,
  BarChart3, Terminal, MessageSquare, Wrench, FileText, FolderKanban,
  Settings,
};

const NAV = [
  { href: "/overview", icon: "LayoutDashboard", label: "Overview" },
  { href: "/agents", icon: "Bot", label: "Agents" },
  { href: "/graph", icon: "Network", label: "Graph" },
  { href: "/findings", icon: "AlertTriangle", label: "Findings" },
  { href: "/targets", icon: "Target", label: "Targets" },
  { href: "/recon", icon: "Radar", label: "Recon" },
  { href: "/insights", icon: "BarChart3", label: "Insights" },
  { divider: true, href: "", icon: "", label: "" },
  { href: "/terminal", icon: "Terminal", label: "Terminal" },
  { href: "/chat", icon: "MessageSquare", label: "Chat" },
  { href: "/cypherfix", icon: "Wrench", label: "CypherFix" },
  { href: "/reports", icon: "FileText", label: "Reports" },
  { divider: true, href: "", icon: "", label: "" },
  { href: "/projects", icon: "FolderKanban", label: "Projects" },
  { href: "/settings", icon: "Settings", label: "Settings" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 h-full w-56 bg-zinc-950 border-r border-zinc-800 flex flex-col z-50">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center text-xs font-bold text-black">
            V
          </div>
          <div>
            <div className="text-sm font-bold text-white">VIPER</div>
            <div className="text-[10px] text-zinc-500 tracking-wider">5.0 MULTI-AGENT</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV.map((item, i) =>
          item.divider ? (
            <div key={`d${i}`} className="my-2 mx-3 border-t border-zinc-800" />
          ) : (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-3 px-4 py-2 mx-2 rounded-md text-sm transition-colors",
                pathname === item.href
                  ? "bg-zinc-800 text-cyan-400"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              {ICONS[item.icon] &&
                (() => {
                  const Icon = ICONS[item.icon];
                  return <Icon size={16} />;
                })()}
              {item.label}
            </Link>
          )
        )}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-zinc-800 text-[10px] text-zinc-600">
        VIPER 5.0 &middot; Next.js Dashboard
      </div>
    </aside>
  );
}
