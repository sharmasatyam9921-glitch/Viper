"use client";

import { useEffect, useRef, useState } from "react";
import { useWebSocket } from "@/hooks/useWebSocket";
import { Activity } from "lucide-react";

interface StreamEvent {
  id: string;
  ts: number;
  type: string;
  severity?: string;
  title: string;
  detail?: string;
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

function titleFor(type: string, payload: Record<string, unknown>): string {
  switch (type) {
    case "finding":     return String(payload.title || payload.vuln_type || "Finding");
    case "phase_start": return `Phase started — ${payload.phase ?? ""}`;
    case "phase_done":  return `Phase complete — ${payload.phase ?? ""}`;
    case "worker_start":return `Worker started — ${payload.technique ?? ""}`;
    case "worker_done": return `Worker finished — ${payload.technique ?? ""}`;
    case "log":         return String(payload.text || payload.message || "log");
    case "hunt_start":  return `Hunt started — ${payload.target ?? ""}`;
    case "hunt_done":   return `Hunt complete — ${payload.target ?? ""}`;
    default:            return type;
  }
}

export function ActivityStream({ limit = 30 }: { limit?: number }) {
  const { on, connected } = useWebSocket();
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const seq = useRef(0);

  useEffect(() => {
    const types = [
      "finding", "phase_start", "phase_done",
      "worker_start", "worker_done", "log",
      "hunt_start", "hunt_done",
    ];
    const offs = types.map((t) =>
      on(t, (msg) => {
        const payload = (msg.payload || msg.data || {}) as Record<string, unknown>;
        const ev: StreamEvent = {
          id: `${msg.ts ?? Date.now()}-${seq.current++}`,
          ts: typeof msg.ts === "number" ? msg.ts * 1000 : Date.now(),
          type: msg.type,
          severity: typeof payload.severity === "string" ? payload.severity : undefined,
          title: titleFor(msg.type, payload),
          detail: typeof payload.target === "string"
            ? payload.target
            : typeof payload.url === "string"
              ? (payload.url as string)
              : undefined,
        };
        setEvents((cur) => [ev, ...cur].slice(0, limit));
      })
    );
    return () => offs.forEach((off) => off());
  }, [on, limit]);

  return (
    <div className="card p-0 overflow-hidden flex flex-col" style={{ minHeight: 320 }}>
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: "1px solid var(--border-1)" }}
      >
        <div className="flex items-center gap-2">
          <Activity size={14} strokeWidth={1.7} style={{ color: "var(--ink-3)" }} />
          <span className="kicker" style={{ color: "var(--ink-2)" }}>
            Live activity
          </span>
        </div>
        <div className="text-xs" style={{ color: connected ? "var(--success)" : "var(--ink-3)" }}>
          {connected ? "streaming" : "idle"}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="p-6 text-center text-sm" style={{ color: "var(--ink-3)" }}>
            Waiting for events…
          </div>
        )}
        {events.map((ev) => (
          <div
            key={ev.id}
            className="fade-in px-4 py-2.5 flex items-start gap-3 text-sm"
            style={{ borderBottom: "1px solid var(--border-1)" }}
          >
            <span
              className="font-mono text-xs pt-0.5"
              style={{ color: "var(--ink-3)" }}
            >
              {fmtTime(ev.ts)}
            </span>
            <div className="flex-1 min-w-0">
              <div style={{ color: "var(--ink-1)" }} className="truncate">
                {ev.title}
              </div>
              {ev.detail && (
                <div
                  className="text-xs mt-0.5 truncate"
                  style={{ color: "var(--ink-3)" }}
                >
                  {ev.detail}
                </div>
              )}
            </div>
            {ev.severity && (
              <span
                className="pill"
                style={{
                  background: `var(--${ev.severity}-soft)`,
                  color: `var(--${ev.severity})`,
                  textTransform: "capitalize",
                }}
              >
                {ev.severity}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
