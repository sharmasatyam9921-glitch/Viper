/**
 * VIPER API Adapter
 *
 * Maps VIPER's frontend API calls to VIPER's Python backend at localhost:8080.
 * This is the bridge between VIPER's Next.js frontend and VIPER's Python server.
 */

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080';

export async function viperFetch(path: string, options?: RequestInit) {
  const url = `${VIPER_API}${path}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });
    if (!res.ok) {
      console.warn(`VIPER API ${path}: ${res.status}`);
      return null;
    }
    return res.json();
  } catch (err) {
    console.warn(`VIPER API ${path} failed:`, err);
    return null;
  }
}

// ── Endpoint mappings ──

export const ViperAPI = {
  // Overview & Status
  getOverview: () => viperFetch('/api/overview'),
  getRiskScore: () => viperFetch('/api/risk-score'),
  getState: () => viperFetch('/api/state'),

  // Agent
  getAgentStatus: () => viperFetch('/api/agent/status'),
  getAgentThinking: () => viperFetch('/api/agent/thinking'),
  approveAction: (data: any) => viperFetch('/api/agent/approve', { method: 'POST', body: JSON.stringify(data) }),
  sendGuidance: (msg: string) => viperFetch('/api/agent/guidance', { method: 'POST', body: JSON.stringify({ guidance: msg }) }),

  // Findings
  getFindings: () => viperFetch('/api/findings'),
  getFindingsTimeline: () => viperFetch('/api/findings/timeline'),
  getFindingsByType: () => viperFetch('/api/findings/by-type'),
  getFindingsBySeverity: () => viperFetch('/api/findings/by-severity'),

  // Attacks
  getAttackStats: () => viperFetch('/api/attacks/stats'),
  getAttackHistory: () => viperFetch('/api/attacks/history'),
  getKillChain: () => viperFetch('/api/attacks/kill-chain'),
  getAttackGraph: () => viperFetch('/api/attack-graph'),

  // Graph
  getGraph: () => viperFetch('/api/graph'),
  getGraphStats: () => viperFetch('/api/graph/stats'),
  queryGraph: (query: string) => viperFetch('/api/graph/query', { method: 'POST', body: JSON.stringify({ query }) }),

  // EvoGraph
  getEvoSessions: () => viperFetch('/api/evograph/sessions'),
  getEvoStats: () => viperFetch('/api/evograph/stats'),
  getFailureLessons: () => viperFetch('/api/v5/failure-lessons'),

  // Scan
  startScan: (target: string, options?: any) => viperFetch('/api/scan/start', { method: 'POST', body: JSON.stringify({ target, ...options }) }),
  getScanStatus: () => viperFetch('/api/scan/status'),

  // Chat
  sendChat: (message: string) => viperFetch('/api/chat/send', { method: 'POST', body: JSON.stringify({ message }) }),
  getChatHistory: () => viperFetch('/api/chat/history'),

  // Terminal
  executeCommand: (cmd: string) => viperFetch('/api/terminal/execute', { method: 'POST', body: JSON.stringify({ command: cmd }) }),
  nlpCommand: (text: string) => viperFetch('/api/terminal/nlp', { method: 'POST', body: JSON.stringify({ text }) }),

  // Settings
  getSettings: () => viperFetch('/api/settings'),
  saveSettings: (data: any) => viperFetch('/api/settings', { method: 'POST', body: JSON.stringify(data) }),

  // Projects
  getProjects: () => viperFetch('/api/projects'),
  createProject: (data: any) => viperFetch('/api/projects', { method: 'POST', body: JSON.stringify(data) }),

  // Templates
  getTemplates: () => viperFetch('/api/templates'),

  // Triage
  getTriageFindings: () => viperFetch('/api/triage/findings'),

  // Export
  exportExcel: () => viperFetch('/api/export/excel'),

  // Modules (v5)
  getModules: () => viperFetch('/api/v5/modules'),
  getEvolution: () => viperFetch('/api/v5/evolution'),

  // WebSocket
  getWSUrl: () => `${VIPER_API.replace('http', 'ws')}/ws`,
  getSSEUrl: () => `${VIPER_API}/api/stream`,
};
