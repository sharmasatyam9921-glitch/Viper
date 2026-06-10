"use client";

import { useState, useEffect, useRef } from "react";
import { apiGet, apiPost } from "@/lib/api";
import type { ChatMessage } from "@/lib/types";
import { Send, Wrench, MessageSquare, User } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";

function ThinkingDots() {
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--brand)", animation: "bounce 1.4s infinite", animationDelay: "0ms" }} />
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--brand)", animation: "bounce 1.4s infinite", animationDelay: "180ms" }} />
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--brand)", animation: "bounce 1.4s infinite", animationDelay: "360ms" }} />
    </div>
  );
}

function ToolMessage({ msg }: { msg: ChatMessage }) {
  return (
    <div
      className="rounded-lg p-3"
      style={{ background: "var(--surface-2)", border: "1px solid var(--border-1)" }}
    >
      <div className="flex items-center gap-2 mb-2">
        <Wrench size={12} style={{ color: "var(--medium)" }} />
        <span className="kicker" style={{ color: "var(--medium)" }}>
          Tool · {msg.tool_name ?? "unknown"}
        </span>
      </div>
      <pre
        className="whitespace-pre-wrap text-xs max-h-48 overflow-y-auto"
        style={{ color: "var(--ink-2)", fontFamily: "var(--font-geist-mono)" }}
      >
        {msg.content}
      </pre>
    </div>
  );
}

function ApprovalDialog({
  data, onRespond,
}: { data: Record<string, unknown>; onRespond: (approved: boolean) => void }) {
  return (
    <div
      className="rounded-lg p-4"
      style={{ background: "var(--medium-soft)", border: "1px solid var(--medium)" }}
    >
      <div className="text-sm font-medium mb-2" style={{ color: "var(--medium)" }}>
        Approval required
      </div>
      <pre
        className="text-xs mb-3 whitespace-pre-wrap max-h-32 overflow-y-auto"
        style={{ color: "var(--ink-1)", fontFamily: "var(--font-geist-mono)" }}
      >
        {JSON.stringify(data, null, 2)}
      </pre>
      <div className="flex gap-2">
        <button onClick={() => onRespond(true)} className="btn-primary">Approve</button>
        <button
          onClick={() => onRespond(false)}
          className="btn-ghost"
          style={{ color: "var(--critical)" }}
        >
          Deny
        </button>
      </div>
    </div>
  );
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const poll = async () => {
      const data = await apiGet<ChatMessage[]>("/api/chat/history");
      if (data) setMessages(data);
    };
    poll();
    intervalRef.current = setInterval(poll, 3000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async () => {
    const text = input.trim();
    if (!text || sending) return;
    setSending(true);
    setInput("");
    setMessages((p) => [...p, { role: "user", content: text, timestamp: new Date().toISOString() }]);
    await apiPost("/api/chat/send", { message: text });
    setSending(false);
  };

  const handleApproval = async (approved: boolean) => {
    await apiPost("/api/agent/approve", { approved });
  };

  return (
    <div className="flex flex-col" style={{ height: "calc(100vh - 8rem)" }}>
      <PageHeader
        kicker="Workspace"
        title="Chat"
        subtitle="Talk to VIPER's reasoning engine. Approve tool calls inline."
      />

      <Card padding="none" className="flex-1 overflow-hidden flex flex-col">
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.length === 0 && (
            <div className="text-center mt-12" style={{ color: "var(--ink-3)" }}>
              <MessageSquare size={28} className="mx-auto mb-3 opacity-50" />
              <div className="text-sm">Ask VIPER anything — recon, exploitation, triage, reporting.</div>
            </div>
          )}

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

            if (msg.role === "tool") return <ToolMessage key={i} msg={msg} />;

            if (approvalData) {
              return (
                <ApprovalDialog key={i} data={approvalData} onRespond={handleApproval} />
              );
            }

            const isUser = msg.role === "user";
            return (
              <div key={i} className={`flex gap-3 ${isUser ? "justify-end" : ""} fade-in`}>
                {!isUser && (
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                    style={{
                      background: "var(--brand-soft)",
                      color: "var(--brand)",
                      fontFamily: "var(--font-serif)",
                    }}
                  >
                    V
                  </div>
                )}
                <div
                  className="rounded-2xl px-4 py-2.5 text-sm max-w-[70%]"
                  style={{
                    background: isUser ? "var(--brand)" : "var(--surface-2)",
                    color: isUser ? "white" : "var(--ink-1)",
                  }}
                >
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                </div>
                {isUser && (
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: "var(--surface-2)", color: "var(--ink-2)" }}
                  >
                    <User size={14} />
                  </div>
                )}
              </div>
            );
          })}

          {sending && (
            <div className="flex gap-3 fade-in">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{
                  background: "var(--brand-soft)",
                  color: "var(--brand)",
                  fontFamily: "var(--font-serif)",
                }}
              >
                V
              </div>
              <div
                className="rounded-2xl px-4 py-3"
                style={{ background: "var(--surface-2)" }}
              >
                <ThinkingDots />
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        <div
          className="px-4 py-3 flex items-center gap-2"
          style={{ borderTop: "1px solid var(--border-1)" }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && send()}
            placeholder="Ask VIPER…"
            className="flex-1 px-4 py-2.5 rounded-full outline-none text-sm"
            style={{
              background: "var(--surface-2)",
              color: "var(--ink-1)",
              border: "1px solid var(--border-1)",
            }}
            disabled={sending}
          />
          <button
            onClick={send}
            className="btn-primary"
            disabled={sending || !input.trim()}
          >
            <Send size={14} />
          </button>
        </div>
      </Card>
    </div>
  );
}
