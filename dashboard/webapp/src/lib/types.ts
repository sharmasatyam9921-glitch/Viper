// VIPER 5.0 Dashboard — TypeScript Interfaces
// Maps to Python backend API response shapes (dashboard/server.py)

export interface Overview {
  targets: number;
  findings: number;
  validated: number;
  attacks: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  top_vuln_types: { type: string; count: number }[];
  recent_findings: Finding[];
  waf_count: number;
  live: {
    total_requests: number;
    total_findings: number;
    validated_findings: number;
    false_positives_caught: number;
    sessions_run: number;
    uptime_seconds: number;
  };
}

export interface RiskScore {
  score: number;
  grade: string;
  breakdown: Record<string, number>;
  trend: string;
  critical: number;
  high: number;
  medium: number;
}

export interface Finding {
  id: number;
  vuln_type: string;
  severity: string;
  title: string;
  url: string;
  domain?: string;
  confidence: number;
  validated: boolean;
  reported?: boolean;
  found_at?: string;
  payload?: string;
  evidence?: string;
  cvss?: number;
  cwe?: string;
}

export interface FindingsPage {
  findings: Finding[];
  total: number;
  page: number;
  limit: number;
  pages: number;
}

export interface Target {
  id: number;
  domain: string;
  url: string;
  technologies: string[];
  finding_count: number;
  attack_count: number;
  subdomain_count?: number;
  ip?: string;
  waf?: string;
  last_scanned?: string;
  status?: string;
}

export interface AttackStat {
  attack_type: string;
  total: number;
  wins: number;
  avg_time_ms: number;
  success_rate: number;
}

export interface LogEntry {
  text: string;
  level: string;
  time?: string;
}

export interface ReconJob {
  id: string;
  target: string;
  status: "starting" | "running" | "completed" | "error" | "cancelled";
  started_at: number;
  phases_done: string[];
  phase_timings: Record<string, number>;
  parallel_groups: ParallelGroup[];
  summary: Record<string, number | boolean>;
  error?: string | null;
}

export interface ParallelGroup {
  phase: number;
  name: string;
  tasks: number;
  duration_sec: number;
  sources: string[];
}

export interface AgentMonitor {
  agents: AgentInfo[];
  bus_messages: number;
  active_scans: number;
  current_target: string;
  current_phase: string;
}

export interface AgentInfo {
  name: string;
  status: string;
  findings: number;
  uptime: number;
  activity_count: number;
}

export interface ReACTStep {
  step: number;
  total_steps: number;
  reward: number;
  q_table_size: number;
  think: string;
  action: string;
  observation: string;
  step_reward: number;
  deep_think: string;
}

export interface Session {
  id: number;
  target: string;
  state: string;
  phase: string;
  iteration: number;
  findings_count: number;
  created_at: string;
  started_at?: string;
  ended_at?: string;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp?: string;
  tool_name?: string;
}

export interface KBResult {
  title: string;
  content: string;
  source: string;
  category: string;
  score: number;
}

export interface WSMessage {
  type: string;
  payload?: Record<string, unknown>;
  data?: Record<string, unknown>;
  ts?: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

// ── HackMode (swarm) shapes — Phase 4 ────────────────────────────────────

export interface HuntSummary {
  hunt_id: string;
  target: string | null;
  started_at: number;
  last_event_at: number;
  event_count: number;
  finding_count: number;
}

export interface HuntsResponse {
  hunts: HuntSummary[];
}

export interface PhaseStats {
  phase: string;
  started_at: number;
  completed_at: number | null;
  workers_dispatched: number;
  workers_completed: number;
  workers_failed: number;
  findings_count: number;
}

export interface WorkerSnapshot {
  worker_id: string;
  phase: string;
  started_at: number;
  last_seen: number;
  last_action: string;
  duration_ms: number | null;
  outcome: string | null;
  findings_count: number;
}

export interface HuntFinding {
  ts: number;
  phase: string;
  severity: string;
  actor: string | null;
  payload: Record<string, unknown>;
}

export interface HuntSnapshot {
  hunt_id: string;
  found: boolean;
  phases: PhaseStats[];
  workers: WorkerSnapshot[];
  findings: HuntFinding[];
}

export interface AuditEvent {
  event_id: string;
  hunt_id: string;
  ts: number;
  action: string;
  phase: string | null;
  actor: string | null;
  target: string | null;
  duration_ms: number | null;
  outcome: string | null;
  findings_count: number;
  severity: string | null;
  payload: Record<string, unknown>;
}

export interface AuditQueryResponse {
  hunt_id: string;
  events: AuditEvent[];
  count: number;
}

// Phases the swarm runs through, in order. Used by PhaseRibbon.
export const HACK_PHASES = ["recon", "vuln", "exploit", "post"] as const;
export type HackPhase = (typeof HACK_PHASES)[number];
