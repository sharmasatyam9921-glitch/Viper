"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";

interface TermLine {
  type: "input" | "output" | "error";
  text: string;
}

/* ---------- page ---------- */
export default function TerminalPage() {
  const [lines, setLines] = useState<TermLine[]>([
    { type: "output", text: "VIPER 5.0 Terminal - Type commands or toggle NLP mode" },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [nlpMode, setNlpMode] = useState(false);
  const [running, setRunning] = useState(false);

  /* SSH state */
  const [sshTarget, setSshTarget] = useState("");
  const [sshUser, setSshUser] = useState("");
  const [sshPort, setSshPort] = useState("22");
  const [showSsh, setShowSsh] = useState(false);

  const outputRef = useRef<HTMLDivElement>(null);

  /* auto-scroll */
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [lines]);

  /* execute command */
  const execute = async () => {
    const cmd = input.trim();
    if (!cmd || running) return;

    setHistory((prev) => [cmd, ...prev]);
    setHistIdx(-1);
    setInput("");
    setLines((prev) => [...prev, { type: "input", text: `$ ${cmd}` }]);
    setRunning(true);

    try {
      let finalCmd = cmd;

      /* NLP translation */
      if (nlpMode) {
        const nlpResult = await apiPost<{ command: string }>("/api/terminal/nlp", {
          text: cmd,
        });
        if (nlpResult?.command) {
          finalCmd = nlpResult.command;
          setLines((prev) => [
            ...prev,
            { type: "output", text: `[NLP] Translated: ${finalCmd}` },
          ]);
        }
      }

      /* execute */
      const result = await apiPost<{ output: string; exit_code: number }>(
        "/api/terminal/execute",
        { cmd: finalCmd },
      );

      if (result) {
        const lineType = result.exit_code === 0 ? "output" : "error";
        setLines((prev) => [...prev, { type: lineType, text: result.output }]);
      } else {
        setLines((prev) => [
          ...prev,
          { type: "error", text: "Error: no response from server" },
        ]);
      }
    } catch {
      setLines((prev) => [
        ...prev,
        { type: "error", text: "Error: request failed" },
      ]);
    }

    setRunning(false);
  };

  /* SSH connect */
  const connectSsh = async () => {
    const result = await apiPost<{ output: string }>("/api/terminal/connect", {
      target: sshTarget,
      user: sshUser,
      port: parseInt(sshPort, 10),
    });
    if (result) {
      setLines((prev) => [...prev, { type: "output", text: result.output }]);
    }
    setShowSsh(false);
  };

  /* key handler */
  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      execute();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length > 0) {
        const next = Math.min(histIdx + 1, history.length - 1);
        setHistIdx(next);
        setInput(history[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx > 0) {
        const next = histIdx - 1;
        setHistIdx(next);
        setInput(history[next]);
      } else {
        setHistIdx(-1);
        setInput("");
      }
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)]">
      {/* header */}
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold text-zinc-100">Terminal</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowSsh(!showSsh)}
            className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:border-cyan-500 transition-colors"
          >
            SSH Connect
          </button>
          <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
            <div
              onClick={() => setNlpMode(!nlpMode)}
              className={`relative w-9 h-5 rounded-full transition-colors ${nlpMode ? "bg-cyan-600" : "bg-zinc-700"}`}
            >
              <div
                className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${nlpMode ? "translate-x-4" : ""}`}
              />
            </div>
            NLP Mode
          </label>
        </div>
      </div>

      {/* SSH form */}
      {showSsh && (
        <div className="mb-3 rounded-lg border border-zinc-700 bg-zinc-900 p-4 flex gap-3 items-end">
          <div className="flex-1">
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Target
            </label>
            <input
              type="text"
              value={sshTarget}
              onChange={(e) => setSshTarget(e.target.value)}
              placeholder="192.168.1.1"
              className="mt-1 w-full rounded bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="w-32">
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider">
              User
            </label>
            <input
              type="text"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="root"
              className="mt-1 w-full rounded bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="w-20">
            <label className="text-[10px] text-zinc-500 uppercase tracking-wider">
              Port
            </label>
            <input
              type="text"
              value={sshPort}
              onChange={(e) => setSshPort(e.target.value)}
              className="mt-1 w-full rounded bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={connectSsh}
            className="rounded-md bg-cyan-600 hover:bg-cyan-500 px-4 py-1.5 text-xs font-semibold text-white transition-colors"
          >
            Connect
          </button>
        </div>
      )}

      {/* terminal output */}
      <div
        ref={outputRef}
        className="flex-1 overflow-y-auto rounded-xl bg-black border border-zinc-800 p-4 font-mono text-sm"
      >
        {lines.map((line, i) => (
          <div
            key={i}
            className={
              line.type === "input"
                ? "text-cyan-400"
                : line.type === "error"
                  ? "text-red-400"
                  : "text-green-400"
            }
          >
            <pre className="whitespace-pre-wrap">{line.text}</pre>
          </div>
        ))}
        {running && (
          <span className="text-zinc-500 animate-pulse">Running...</span>
        )}
      </div>

      {/* input */}
      <div className="mt-2 flex items-center gap-2 rounded-lg bg-black border border-zinc-800 px-4 py-2 font-mono">
        <span className="text-green-400 text-sm">$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={nlpMode ? "Describe what you want to do..." : "Enter command..."}
          className="flex-1 bg-transparent text-sm text-green-400 placeholder-zinc-600 focus:outline-none"
          autoFocus
        />
      </div>
    </div>
  );
}
