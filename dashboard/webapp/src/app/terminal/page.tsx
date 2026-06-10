"use client";

import { useState, useEffect, useRef } from "react";
import { apiPost } from "@/lib/api";
import { Terminal as TerminalIcon, Sparkles, Server } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";

interface TermLine {
  type: "input" | "output" | "error" | "nlp";
  text: string;
}

export default function TerminalPage() {
  const [lines, setLines] = useState<TermLine[]>([
    { type: "output", text: "VIPER 6.0 sandboxed terminal — type a command or toggle NLP mode" },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [nlpMode, setNlpMode] = useState(false);
  const [running, setRunning] = useState(false);

  const [showSsh, setShowSsh] = useState(false);
  const [sshTarget, setSshTarget] = useState("");
  const [sshUser, setSshUser] = useState("");
  const [sshPort, setSshPort] = useState("22");

  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [lines]);

  const execute = async () => {
    const cmd = input.trim();
    if (!cmd || running) return;
    setHistory((p) => [cmd, ...p]);
    setHistIdx(-1);
    setInput("");
    setLines((p) => [...p, { type: "input", text: `$ ${cmd}` }]);
    setRunning(true);
    try {
      let finalCmd = cmd;
      if (nlpMode) {
        const r = await apiPost<{ command: string }>("/api/terminal/nlp", { text: cmd });
        if (r?.command) {
          finalCmd = r.command;
          setLines((p) => [...p, { type: "nlp", text: `→ ${finalCmd}` }]);
        }
      }
      const res = await apiPost<{ output: string; exit_code: number }>(
        "/api/terminal/execute", { cmd: finalCmd });
      if (res) {
        setLines((p) => [...p, { type: res.exit_code === 0 ? "output" : "error", text: res.output }]);
      } else {
        setLines((p) => [...p, { type: "error", text: "No response from server" }]);
      }
    } catch {
      setLines((p) => [...p, { type: "error", text: "Request failed" }]);
    }
    setRunning(false);
  };

  const connectSsh = async () => {
    const r = await apiPost<{ output: string }>("/api/terminal/connect", {
      target: sshTarget, user: sshUser, port: parseInt(sshPort, 10),
    });
    if (r) setLines((p) => [...p, { type: "output", text: r.output }]);
    setShowSsh(false);
  };

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") execute();
    else if (e.key === "ArrowUp" && history.length) {
      e.preventDefault();
      const idx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(idx);
      setInput(history[idx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const idx = Math.max(histIdx - 1, -1);
      setHistIdx(idx);
      setInput(idx === -1 ? "" : history[idx]);
    }
  };

  const lineColor = (t: TermLine["type"]) =>
    t === "input"  ? "var(--brand)"
    : t === "error" ? "var(--critical)"
    : t === "nlp"   ? "var(--medium)"
    : "var(--ink-1)";

  return (
    <div className="space-y-5">
      <PageHeader
        kicker="Workspace"
        title="Terminal"
        subtitle="Sandboxed pentest tool runner — allowlist enforced, no local system access."
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setNlpMode(!nlpMode)}
              className="pill cursor-pointer"
              style={{
                background: nlpMode ? "var(--brand-soft)" : "var(--surface-2)",
                color: nlpMode ? "var(--brand-ink)" : "var(--ink-2)",
              }}
            >
              <Sparkles size={11} />
              NLP {nlpMode ? "on" : "off"}
            </button>
            <button onClick={() => setShowSsh(!showSsh)} className="btn-ghost">
              <Server size={13} />
              SSH
            </button>
          </div>
        }
      />

      {showSsh && (
        <Card className="fade-in">
          <div className="kicker mb-2">Connect to target via SSH</div>
          <div className="grid grid-cols-4 gap-2">
            <input
              placeholder="user"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm outline-none"
              style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
            />
            <input
              placeholder="host"
              value={sshTarget}
              onChange={(e) => setSshTarget(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm outline-none col-span-2"
              style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
            />
            <input
              placeholder="22"
              value={sshPort}
              onChange={(e) => setSshPort(e.target.value)}
              className="px-3 py-2 rounded-lg text-sm outline-none"
              style={{ background: "var(--surface-2)", color: "var(--ink-1)" }}
            />
          </div>
          <button onClick={connectSsh} className="btn-primary mt-3">
            Connect
          </button>
        </Card>
      )}

      <Card padding="none" className="overflow-hidden">
        <div
          ref={outputRef}
          className="p-4 overflow-y-auto"
          style={{
            background: "var(--surface-1)",
            height: 540,
            fontFamily: "var(--font-geist-mono)",
            fontSize: 13,
            lineHeight: 1.55,
          }}
        >
          {lines.map((l, i) => (
            <div key={i} style={{ color: lineColor(l.type) }} className="whitespace-pre-wrap fade-in">
              {l.text}
            </div>
          ))}
          {running && (
            <div className="flex items-center gap-1 mt-1" style={{ color: "var(--brand)" }}>
              <span className="w-1 h-1 rounded-full" style={{ background: "currentColor", animation: "pulse 1s infinite" }} />
              running…
            </div>
          )}
        </div>
        <div
          className="px-4 py-3 flex items-center gap-2"
          style={{ borderTop: "1px solid var(--border-1)", background: "var(--surface-2)" }}
        >
          <TerminalIcon size={14} style={{ color: "var(--brand)" }} />
          <span
            style={{ color: "var(--ink-3)", fontFamily: "var(--font-geist-mono)", fontSize: 13 }}
          >
            {nlpMode ? "nlp›" : "$"}
          </span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            placeholder={nlpMode ? "scan example.com for sqli" : "nuclei -u https://target.com -severity high"}
            className="flex-1 bg-transparent outline-none text-sm"
            style={{
              color: "var(--ink-1)",
              fontFamily: "var(--font-geist-mono)",
            }}
            disabled={running}
            autoFocus
          />
        </div>
      </Card>
    </div>
  );
}
