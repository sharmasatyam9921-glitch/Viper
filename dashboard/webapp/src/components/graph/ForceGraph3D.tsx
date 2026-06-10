"use client";

/**
 * 3D knowledge-graph visualization. Lazy-loads the framework-agnostic
 * `3d-force-graph` UMD module on the client only (it touches `window`, so it
 * can never run during SSR) and renders the {nodes, edges} payload from
 * `/api/graph`. Ported from the legacy :8080 SPA so the unified dashboard
 * keeps the same spatial view of targets → techniques → findings.
 */

import { useEffect, useRef, useState } from "react";
import { apiGet } from "@/lib/api";

interface GraphNode {
  id: string;
  name: string;
  label?: string;
  type: string;
  color: string;
  val: number;
  severity?: string;
  phase?: string;
}
interface GraphEdge {
  source: string;
  target: string;
  rel?: string;
}
interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// Minimal structural surface for the parts of the 3d-force-graph instance we
// drive, plus its constructor. The library ships rich generic types, but we
// bridge to this simplified shape (via a single localized cast) so our
// accessors stay typed against our own node/edge shapes instead of fighting
// the library's NodeObject variance.
type FGInstance = {
  graphData: (d: { nodes: GraphNode[]; links: GraphEdge[] }) => FGInstance;
  backgroundColor: (c: string) => FGInstance;
  nodeLabel: (fn: (n: GraphNode) => string) => FGInstance;
  nodeColor: (fn: (n: GraphNode) => string) => FGInstance;
  nodeVal: (fn: (n: GraphNode) => number) => FGInstance;
  nodeRelSize: (n: number) => FGInstance;
  nodeOpacity: (n: number) => FGInstance;
  linkColor: (fn: (l: GraphEdge) => string) => FGInstance;
  linkWidth: (n: number) => FGInstance;
  linkDirectionalParticles: (n: number) => FGInstance;
  linkDirectionalParticleWidth: (n: number) => FGInstance;
  width: (n: number) => FGInstance;
  height: (n: number) => FGInstance;
  onNodeClick: (fn: (n: GraphNode) => void) => FGInstance;
  _destructor?: () => void;
};
type FGConstructor = new (el: HTMLElement) => FGInstance;

function cssVar(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return v || fallback;
}

export function ForceGraph3D({
  huntId, height = 520,
}: {
  huntId?: string;
  height?: number;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<FGInstance | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "empty" | "error">(
    "loading",
  );
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    let disposed = false;
    const el = containerRef.current;
    if (!el) return;

    (async () => {
      // Pull data and the renderer in parallel.
      const url = huntId
        ? `/api/graph?hunt_id=${encodeURIComponent(huntId)}`
        : "/api/graph";
      let data: GraphPayload | null = null;
      let Ctor: FGConstructor | null = null;
      try {
        const [d, mod] = await Promise.all([
          apiGet<GraphPayload>(url),
          import("3d-force-graph"),
        ]);
        data = d;
        // v1.80 default export is a constructor: `new ForceGraph3D(el)`.
        Ctor = mod.default as unknown as FGConstructor;
      } catch {
        if (!disposed) setStatus("error");
        return;
      }
      if (disposed) return;
      if (!data || !data.nodes || data.nodes.length === 0) {
        setStatus("empty");
        return;
      }

      const width = el.clientWidth || 800;
      const graph = new Ctor(el)
        .backgroundColor(cssVar("--surface-0", "#0b0d12"))
        .nodeLabel((n) => `${n.label ?? n.name} · ${n.type}`)
        .nodeColor((n) => n.color || "#6b7280")
        .nodeVal((n) => n.val || 4)
        .nodeRelSize(4)
        .nodeOpacity(0.92)
        .linkColor(() => cssVar("--border-1", "#2a2f3a"))
        .linkWidth(0.5)
        .linkDirectionalParticles(2)
        .linkDirectionalParticleWidth(1.4)
        .width(width)
        .height(height)
        .onNodeClick((n) => setSelected(n));

      // The backend ships `edges`; the renderer wants `links`.
      graph.graphData({ nodes: data.nodes, links: data.edges ?? [] });
      graphRef.current = graph;
      setStatus("ready");
    })();

    const onResize = () => {
      const g = graphRef.current;
      if (g && el) g.width(el.clientWidth || 800);
    };
    window.addEventListener("resize", onResize);

    return () => {
      disposed = true;
      window.removeEventListener("resize", onResize);
      const g = graphRef.current;
      if (g?._destructor) {
        try { g._destructor(); } catch { /* ignore */ }
      }
      graphRef.current = null;
      if (el) el.innerHTML = "";
    };
  }, [huntId, height]);

  return (
    <div className="relative" style={{ height }}>
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {status !== "ready" && (
        <div
          className="absolute inset-0 flex items-center justify-center text-sm"
          style={{ color: "var(--ink-3)" }}
        >
          {status === "loading" && "Loading graph…"}
          {status === "empty" && "No graph data yet — run a hunt to populate it."}
          {status === "error" && "Graph renderer unavailable."}
        </div>
      )}

      {selected && (
        <div
          className="absolute top-3 right-3 max-w-[260px] p-3 rounded-lg fade-in"
          style={{
            background: "color-mix(in oklab, var(--surface-0) 92%, transparent)",
            border: "1px solid var(--border-1)",
            backdropFilter: "blur(8px)",
          }}
        >
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className="kicker">{selected.type}</span>
            <button
              onClick={() => setSelected(null)}
              className="text-xs"
              style={{ color: "var(--ink-3)" }}
              aria-label="close"
            >
              ✕
            </button>
          </div>
          <div
            className="text-sm break-words"
            style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}
          >
            {selected.label ?? selected.name}
          </div>
          {selected.severity && (
            <div className="mt-1 text-xs" style={{ color: "var(--ink-3)" }}>
              severity: {selected.severity}
              {selected.phase ? ` · ${selected.phase}` : ""}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
