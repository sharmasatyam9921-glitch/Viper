"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { WSMessage } from "@/lib/types";

function getDefaultWsUrl(): string {
  // Direct connection to Python WebSocket backend on :8080.
  // Note: in some Chromium builds this is blocked by cross-port localhost
  // policy (ERR_FAILED). In that case the dashboard falls back to 5s API
  // polling via React Query and displays "Disconnected" in the top bar —
  // functional but not real-time.
  if (typeof window === "undefined") return "ws://localhost:8080/ws";
  const { protocol, hostname } = window.location;
  const wsProtocol = protocol === "https:" ? "wss:" : "ws:";
  return `${wsProtocol}//${hostname}:8080/ws`;
}

export function useWebSocket(urlOverride?: string) {
  const url = urlOverride ?? getDefaultWsUrl();
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const listeners = useRef<Map<string, Set<(msg: WSMessage) => void>>>(
    new Map()
  );

  useEffect(() => {
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let alive = true;

    function connect() {
      if (!alive) return;
      try {
        const socket = new WebSocket(url);
        ws.current = socket;

        socket.onopen = () => setConnected(true);
        socket.onclose = () => {
          setConnected(false);
          if (alive) reconnectTimer = setTimeout(connect, 3000);
        };
        socket.onerror = () => socket.close();
        socket.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data) as WSMessage;
            setLastMessage(msg);
            const handlers = listeners.current.get(msg.type);
            if (handlers) handlers.forEach((fn) => fn(msg));
          } catch {
            /* ignore non-JSON */
          }
        };
      } catch {
        if (alive) reconnectTimer = setTimeout(connect, 3000);
      }
    }

    connect();
    return () => {
      alive = false;
      clearTimeout(reconnectTimer);
      ws.current?.close();
    };
  }, [url]);

  const send = useCallback((data: Record<string, unknown>) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    }
  }, []);

  const on = useCallback(
    (type: string, handler: (msg: WSMessage) => void) => {
      if (!listeners.current.has(type)) {
        listeners.current.set(type, new Set());
      }
      listeners.current.get(type)!.add(handler);
      return () => {
        listeners.current.get(type)?.delete(handler);
      };
    },
    []
  );

  return { connected, lastMessage, send, on };
}
