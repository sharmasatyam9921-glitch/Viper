export const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "LayoutDashboard" },
  { id: "agents", label: "Agents", icon: "Bot" },
  { id: "graph", label: "Graph", icon: "Network" },
  { id: "findings", label: "Findings", icon: "AlertTriangle" },
  { id: "targets", label: "Targets", icon: "Target" },
  { id: "recon", label: "Recon", icon: "Radar" },
  { id: "insights", label: "Insights", icon: "BarChart3" },
  { id: "divider1", divider: true },
  { id: "terminal", label: "Terminal", icon: "Terminal" },
  { id: "chat", label: "Chat", icon: "MessageSquare" },
  { id: "cypherfix", label: "CypherFix", icon: "Wrench" },
  { id: "reports", label: "Reports", icon: "FileText" },
  { id: "divider2", divider: true },
  { id: "projects", label: "Projects", icon: "FolderKanban" },
  { id: "settings", label: "Settings", icon: "Settings" },
] as const;

export type NavId = (typeof NAV_ITEMS)[number]["id"];
