"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import type { ChatMessage } from "@/lib/types";

/* ---------- role badge ---------- */
const ROLE_STYLE: Record<string, string> = {
  user: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  assistant: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  tool: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  system: "bg-zinc-700/40 text-zinc-400 border-zinc-600/30",
};

function RoleBadge({ role }: { role: string }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${ROLE_STYLE[role] ?? ROLE_STYLE.system}`}
    >
      {role}
    </span>
  );
}

/* ---------- thinking dots ---------- */
function ThinkingDots() {
  return (
    <div className="flex items-center gap-1 px-4 py-3">
      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce [animation-delay:0ms]" />
      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce [animation-delay:150ms]" />
      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce [animation-delay:300ms]" />
    </div>
  );
}

/* ---------- tool card ---------- */
function ToolCard({ msg }: { msg: ChatMessage }) {
  return (
    <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3 font-mono text-xs">
      <div className="flex items-center gap-2 mb-2">
        <RoleBadge role="tool" />
        {msg.tool_name && (
          <span className="text-purple-300 font-semibold">{msg.tool_name}</span>
        )}
      </div>
      <pre className="whitespace-pre-wrap text-zinc-400 max-h-48 overflow-y-auto">
        {msg.content}
      </pre>
    </div>
  );
}

/* ---------- approval dialog ---------- */
function ApprovalDialog({
  data,
  onRespond,
}: {
  data: Record<string, unknown>;
  onRespond: (approved: boolean) => void;
}) {
  return (
    <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4">
      <p className="text-sm font-semibold text-yellow-400 mb-2">
        Approval Required
      </p>
      <pre className="text-xs text-zinc-300 mb-3 whitespace-pre-wrap font-mono max-h-32 overflow-y-auto">
        {JSON.stringify(data, null, 2)}
      </pre>
      <div className="flex gap-2">
        <button
          onClick={() => onRespond(true)}
          className="rounded-md bg-emerald-600 hover:bg-emerald-500 px-4 py-1.5 text-xs font-semibold text-white transition-colors"
        >
          Approve
        </button>
        <button
          onClick={() => onRespond(false)}
          className="rounded-md bg-red-600 hover:bg-red-500 px-4 py-1.5 text-xs font-semibold text-white transition-colors"
        >
          Deny
        </button>
      </div>
    </div>
  );
}

/* ---------- page ---------- */
export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /* poll history */
  useEffect(() => {
    const poll = async () => {
      const data = await apiGet<ChatMessage[]>("/api/chat/history");
      if (data) setMessages(data);
    };
    poll();
    intervalRef.current = setInterval(poll, 3000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  /* auto-scroll */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  /* send message */
  const send = async () => {
    const text = input.trim();
    if (!text || sending) return;
    setSending(true);
    setInput("");
    setMessages((prev) => [
      ...prev,
      { role: "user", content: text, timestamp: new Date().toISOString() },
    ]);
    await apiPost("/api/chat/send", { message: text });
    setSending(false);
  };

  /* approval handler */
  const handleApproval = async (approved: boolean) => {
    await apiPost("/api/agent/approve", { approved });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)]">
      <h1 className="text-xl font-bold text-zinc-100 mb-4">AI Chat</h1>

      {/* message list */}
      <div className="flex-1 overflow-y-auto rounded-xl bg-zinc-900 border border-zinc-800 p-4 space-y-3">
        {messages.map((msg, i) => {
          const approvalData =
            msg.role === "assistant" &&
            typeof msg.content === "string" &&
            msg.content.includes("approval_request")
              ? (() => {
                  try {
                    const parsed = JSON.parse(msg.content);
                    return parsed.approval_request ?? null;
                  } catch {
                    return null;
                  }
                })()
              : null;

          if (msg.role === "tool") {
            return <ToolCard key={i} msg={msg} />;
          }

          return (
            <div key={i} className="space-y-1">
              <div className="flex items-center gap-2">
                <RoleBadge role={msg.role} />
                {msg.timestamp && (
                  <span className="text-[10px] text-zinc-600">
                    {msg.timestamp}
                  </span>
                )}
              </div>
              <div className="pl-1 text-sm text-zinc-300 whitespace-pre-wrap">
                {msg.content}
              </div>
              {approvalData && (
                <ApprovalDialog
                  data={approvalData}
                  onRespond={handleApproval}
                />
              )}
            </div>
          );
        })}

        {sending && <ThinkingDots />}
        <div ref={bottomRef} />
      </div>

      {/* input */}
      <div className="mt-3 flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Type a message..."
          className="flex-1 rounded-lg bg-zinc-900 border border-zinc-700 px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 transition-colors"
        />
        <button
          onClick={send}
          disabled={sending || !input.trim()}
          className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed px-5 py-2.5 text-sm font-semibold text-white transition-colors"
        >
          Send
        </button>
      </div>
    </div>
  );
}
