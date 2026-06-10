"use client";

import { useState, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet } from "@/lib/api";
import { Network, Send } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ForceGraph3D } from "@/components/graph/ForceGraph3D";

interface GraphStats {
  node_count: number;
  edge_count: number;
  node_types?: Record<string, number>;
  edge_types?: Record<string, number>;
}
interface QueryResult {
  columns?: string[];
  rows?: Record<string, unknown>[];
  raw?: unknown;
  error?: string;
}

const PRESETS = [
  { label: "All target nodes",   q: "MATCH (n:Target) RETURN n LIMIT 25" },
  { label: "Findings → Targets", q: "MATCH (f:Finding)-[:ON]->(t:Target) RETURN f, t LIMIT 25" },
  { label: "Attack chains",      q: "MATCH p=(a)-[:LEADS_TO*]->(b) RETURN p LIMIT 10" },
  { label: "Critical findings",  q: "MATCH (f:Finding {severity:'critical'}) RETURN f LIMIT 50" },
];

export default function GraphPage() {
  const { data: stats } = useApi<GraphStats>("graph-stats", "/api/graph/stats", 10000);
  const [query, setQuery] = useState("MATCH (n) RETURN n LIMIT 25");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [running, setRunning] = useState(false);
  // Monotonic token so a slow earlier query can't overwrite a newer result.
  const reqIdRef = useRef(0);

  const run = async () => {
    if (!query.trim()) return;
    const myReq = ++reqIdRef.current;
    setRunning(true);
    const r = await apiGet<QueryResult>(`/api/graph/query?q=${encodeURIComponent(query)}`);
    // A newer query was fired while this one was in flight — discard the stale
    // response and let the latest request settle the UI.
    if (myReq !== reqIdRef.current) return;
    setResult(r);
    setRunning(false);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Knowledge"
        title="Attack Graph"
        subtitle="Query the knowledge graph — findings, targets, attack chains, MITRE techniques."
        actions={
          stats && (
            <div className="flex items-center gap-4 text-xs" style={{ color: "var(--ink-3)" }}>
              <div>
                <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>{stats.node_count}</span> nodes
              </div>
              <div>
                <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>{stats.edge_count}</span> edges
              </div>
            </div>
          )
        }
      />

      <Card padding="none" className="overflow-hidden">
        <CardHeader
          title="Knowledge map"
          kicker="Targets → techniques → findings"
        />
        <ForceGraph3D height={520} />
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card padding="none">
          <CardHeader title="Node types" kicker="Schema" />
          <div className="p-5 space-y-2">
            {Object.entries(stats?.node_types ?? {}).length === 0 ? (
              <div className="text-sm" style={{ color: "var(--ink-3)" }}>Empty</div>
            ) : Object.entries(stats?.node_types ?? {}).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-sm">
                <span style={{ color: "var(--ink-2)" }}>{k}</span>
                <span className="pill" style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}>{v}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card padding="none">
          <CardHeader title="Edge types" kicker="Relationships" />
          <div className="p-5 space-y-2">
            {Object.entries(stats?.edge_types ?? {}).length === 0 ? (
              <div className="text-sm" style={{ color: "var(--ink-3)" }}>Empty</div>
            ) : Object.entries(stats?.edge_types ?? {}).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-sm">
                <span style={{ color: "var(--ink-2)", fontFamily: "var(--font-geist-mono)" }}>{k}</span>
                <span className="pill" style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}>{v}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card padding="none">
          <CardHeader title="Presets" kicker="Quick queries" />
          <div className="p-5 space-y-1.5">
            {PRESETS.map((p) => (
              <button
                key={p.label}
                onClick={() => setQuery(p.q)}
                className="w-full text-left px-3 py-2 rounded-lg text-sm transition-all"
                style={{ background: "var(--surface-2)", color: "var(--ink-2)" }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "var(--brand-soft)";
                  (e.currentTarget as HTMLElement).style.color = "var(--brand-ink)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "var(--surface-2)";
                  (e.currentTarget as HTMLElement).style.color = "var(--ink-2)";
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        </Card>
      </div>

      <Card padding="none">
        <CardHeader
          title="Cypher console"
          kicker="Query"
          action={
            <button onClick={run} disabled={running} className="btn-primary">
              <Send size={13} />
              {running ? "Running" : "Run"}
            </button>
          }
        />
        <div className="p-5">
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); }}
            rows={4}
            className="w-full p-3 rounded-lg outline-none text-sm"
            style={{
              background: "var(--surface-2)",
              border: "1px solid var(--border-1)",
              color: "var(--ink-1)",
              fontFamily: "var(--font-geist-mono)",
            }}
          />
          <div className="mt-2 text-xs" style={{ color: "var(--ink-3)" }}>
            Press ⌘/Ctrl + Enter to run
          </div>
        </div>
      </Card>

      {result?.error && (
        <Card>
          <div className="kicker mb-2" style={{ color: "var(--critical)" }}>Query error</div>
          <pre className="text-xs p-3 rounded-lg" style={{
            background: "var(--critical-soft)", color: "var(--critical)",
            fontFamily: "var(--font-geist-mono)",
          }}>{result.error}</pre>
        </Card>
      )}

      {result?.rows && result.rows.length > 0 && (
        <Card padding="none" className="overflow-hidden">
          <CardHeader title="Results" kicker={`${result.rows.length} rows`} />
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  {(result.columns ?? Object.keys(result.rows[0])).map((c) => (
                    <th key={c} className="font-normal text-xs uppercase tracking-wider px-5 py-3 text-left"
                        style={{ color: "var(--ink-3)" }}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i} style={{ borderTop: "1px solid var(--border-1)" }}>
                    {(result.columns ?? Object.keys(row)).map((c) => (
                      <td key={c} className="px-5 py-2" style={{
                        color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)", fontSize: 12,
                      }}>{String(row[c] ?? "—").slice(0, 200)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {result?.rows && result.rows.length === 0 && (
        <EmptyState title="No results" hint="Try a preset or adjust the LIMIT." icon={<Network size={20} />} />
      )}
    </div>
  );
}
