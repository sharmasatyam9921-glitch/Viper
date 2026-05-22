"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";

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

/* ---------- page ---------- */
export default function GraphPage() {
  const { data: stats } = useApi<GraphStats>(
    "graph-stats",
    "/api/graph/stats",
    10000,
  );

  const [query, setQuery] = useState("");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<"json" | "table">("table");

  /* run query */
  const runQuery = async () => {
    const q = query.trim();
    if (!q || loading) return;
    setLoading(true);
    const data = await apiGet<QueryResult>(
      `/api/graph/query?q=${encodeURIComponent(q)}`,
    );
    setResult(data);
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-zinc-100">Knowledge Graph</h1>

      {/* 3D graph placeholder */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-8 text-center">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/20 flex items-center justify-center mx-auto mb-4">
          <svg
            className="w-8 h-8 text-cyan-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 3v2.25M12 18.75V21m-4.773-4.227l-1.591 1.591M18.364 5.636l-1.591 1.591M3 12h2.25M18.75 12H21M5.636 5.636L4.045 4.045m14.318 14.318l1.591 1.591M12 9a3 3 0 100 6 3 3 0 000-6z"
            />
          </svg>
        </div>
        <p className="text-sm text-zinc-400">
          3D Force Graph visualization requires{" "}
          <span className="text-cyan-400 font-mono text-xs">
            3d-force-graph
          </span>
        </p>
        <p className="text-xs text-zinc-600 mt-1">
          Install the package and use dynamic import to avoid SSR issues.
        </p>
      </div>

      {/* stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-4">
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
            Nodes
          </p>
          <p className="text-2xl font-bold text-cyan-400 mt-1">
            {stats?.node_count ?? 0}
          </p>
        </div>
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-4">
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">
            Edges
          </p>
          <p className="text-2xl font-bold text-emerald-400 mt-1">
            {stats?.edge_count ?? 0}
          </p>
        </div>

        {/* node types breakdown */}
        {stats?.node_types && (
          <>
            {Object.entries(stats.node_types)
              .slice(0, 2)
              .map(([type, count]) => (
                <div
                  key={type}
                  className="rounded-xl bg-zinc-900 border border-zinc-800 p-4"
                >
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider truncate">
                    {type}
                  </p>
                  <p className="text-2xl font-bold text-zinc-200 mt-1">
                    {count}
                  </p>
                </div>
              ))}
          </>
        )}
      </div>

      {/* query input */}
      <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
        <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
          Graph Query
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runQuery()}
            placeholder="MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 25"
            className="flex-1 rounded-lg bg-zinc-800 border border-zinc-700 px-4 py-2.5 text-sm text-zinc-100 font-mono placeholder-zinc-600 focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <button
            onClick={runQuery}
            disabled={loading || !query.trim()}
            className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 px-5 py-2.5 text-sm font-semibold text-white transition-colors"
          >
            {loading ? "Running..." : "Query"}
          </button>
        </div>

        {/* view mode toggle */}
        {result && (
          <div className="flex gap-2 mt-3">
            <button
              onClick={() => setViewMode("table")}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                viewMode === "table"
                  ? "bg-cyan-600 text-white"
                  : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Table
            </button>
            <button
              onClick={() => setViewMode("json")}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                viewMode === "json"
                  ? "bg-cyan-600 text-white"
                  : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              JSON
            </button>
          </div>
        )}
      </div>

      {/* results */}
      {result && (
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-3">
            Results
          </h2>

          {result.error && (
            <p className="text-sm text-red-400 font-mono">{result.error}</p>
          )}

          {viewMode === "json" && !result.error && (
            <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap max-h-96 overflow-y-auto">
              {JSON.stringify(result.rows ?? result.raw ?? result, null, 2)}
            </pre>
          )}

          {viewMode === "table" &&
            !result.error &&
            result.rows &&
            result.rows.length > 0 && (
              <div className="overflow-x-auto max-h-96 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-700">
                      {(
                        result.columns ??
                        Object.keys(result.rows[0])
                      ).map((col) => (
                        <th
                          key={col}
                          className="px-3 py-2 text-left text-zinc-500 font-semibold uppercase tracking-wider"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((row, i) => (
                      <tr
                        key={i}
                        className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                      >
                        {(
                          result.columns ??
                          Object.keys(row)
                        ).map((col) => (
                          <td
                            key={col}
                            className="px-3 py-2 text-zinc-300 font-mono"
                          >
                            {typeof row[col] === "object"
                              ? JSON.stringify(row[col])
                              : String(row[col] ?? "")}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

          {viewMode === "table" &&
            !result.error &&
            (!result.rows || result.rows.length === 0) && (
              <p className="text-xs text-zinc-500">No results returned.</p>
            )}
        </div>
      )}
    </div>
  );
}
