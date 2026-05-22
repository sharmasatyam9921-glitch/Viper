"use client";

import { useWebSocket } from "@/hooks/useWebSocket";

export function TopBar() {
  const { connected } = useWebSocket();

  return (
    <header className="fixed top-0 left-56 right-0 h-12 bg-zinc-950/80 backdrop-blur border-b border-zinc-800 flex items-center justify-between px-6 z-40">
      <div className="text-sm text-zinc-400">Dashboard</div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              connected ? "bg-emerald-500" : "bg-red-500"
            }`}
          />
          <span className="text-zinc-500">
            {connected ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>
    </header>
  );
}
