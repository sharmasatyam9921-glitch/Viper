"use client";

import { useState } from "react";
import { Play, Square, ShieldAlert } from "lucide-react";
import { apiPost } from "@/lib/api";

const PROFILE_OPTIONS = [
  { id: "full",   label: "Full" ,    blurb: "All 7 phases — recon to report" },
  { id: "stealth",label: "Stealth",  blurb: "Slow + WAF-evading + rotated UA" },
  { id: "quick",  label: "Quick",    blurb: "Recon + light vuln scan" },
  { id: "ai",     label: "AI Hunt",  blurb: "OWASP Top 10 for Agentic AI" },
];

export function HuntPanel() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("full");
  const [busy, setBusy] = useState(false);
  const [last, setLast] = useState<string | null>(null);

  async function start() {
    if (!target.trim()) return;
    setBusy(true);
    try {
      const res = await apiPost<{
        ok?: boolean;
        pid?: number;
        command_preview?: string;
        hunt_id?: string;
        error?: string;
      }>("/api/hack/start", { target: target.trim(), profile });
      if (res && (res.ok || res.pid || res.hunt_id)) {
        const tag =
          res.hunt_id
            ? `Launched · ${res.hunt_id}`
            : res.pid
              ? `Launched · pid ${res.pid}`
              : "Launched";
        setLast(tag);
        setTarget("");
      } else {
        setLast(`Error · ${res?.error || "unknown"}`);
      }
    } catch (e) {
      setLast(`Error · ${(e as Error).message}`);
    } finally {
      setBusy(false);
      setTimeout(() => setLast(null), 4500);
    }
  }

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 kicker mb-1">
            <ShieldAlert size={12} />
            New hunt
          </div>
          <div
            className="display"
            style={{ fontSize: "1.05rem", color: "var(--ink-1)" }}
          >
            Launch from here
          </div>
        </div>
        {last && (
          <span
            className="pill fade-in"
            style={{
              background: last.startsWith("Error")
                ? "var(--critical-soft)"
                : "var(--success-soft)",
              color: last.startsWith("Error")
                ? "var(--critical)"
                : "var(--success)",
            }}
          >
            {last}
          </span>
        )}
      </div>

      {/* Target input */}
      <div className="flex items-center gap-2 mt-3">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") start();
          }}
          placeholder="https://target.example.com"
          className="flex-1 px-3 py-2 rounded-lg text-sm outline-none transition-shadow"
          style={{
            background: "var(--surface-2)",
            color: "var(--ink-1)",
            border: "1px solid var(--border-1)",
            fontFamily: "var(--font-geist-mono)",
          }}
          onFocus={(e) => {
            (e.currentTarget as HTMLElement).style.boxShadow =
              `0 0 0 2px var(--brand-soft)`;
          }}
          onBlur={(e) => {
            (e.currentTarget as HTMLElement).style.boxShadow = "none";
          }}
        />
        <button
          onClick={start}
          className="btn-primary"
          disabled={busy || !target.trim()}
        >
          {busy ? (
            <Square size={13} fill="currentColor" />
          ) : (
            <Play size={13} fill="currentColor" />
          )}
          {busy ? "Launching" : "Hunt"}
        </button>
      </div>

      {/* Profile picker */}
      <div className="grid grid-cols-2 gap-2 mt-3">
        {PROFILE_OPTIONS.map((opt) => (
          <button
            key={opt.id}
            onClick={() => setProfile(opt.id)}
            className="text-left rounded-lg px-3 py-2 transition-all"
            style={{
              background:
                profile === opt.id ? "var(--brand-soft)" : "var(--surface-2)",
              border: `1px solid ${profile === opt.id ? "var(--brand)" : "transparent"}`,
              color:
                profile === opt.id ? "var(--brand-ink)" : "var(--ink-2)",
            }}
          >
            <div className="text-xs font-medium">{opt.label}</div>
            <div
              className="text-[10px] mt-0.5 leading-tight"
              style={{
                color:
                  profile === opt.id ? "var(--brand-ink)" : "var(--ink-3)",
                opacity: 0.85,
              }}
            >
              {opt.blurb}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
