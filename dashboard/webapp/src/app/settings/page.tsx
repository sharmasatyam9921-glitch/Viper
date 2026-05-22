"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";

interface Settings {
  /* general */
  target?: string;
  max_concurrent?: number;
  scan_timeout?: number;
  /* stealth */
  stealth_level?: number;
  waf_evasion?: boolean;
  randomize_ua?: boolean;
  /* model */
  model_deep?: string;
  model_fast?: string;
  model_report?: string;
  /* scan */
  scan_intensity?: string;
  max_iterations?: number;
  nuclei_enabled?: boolean;
  /* notifications */
  discord_webhook?: string;
  telegram_token?: string;
  email_smtp?: string;
  [key: string]: unknown;
}

/* ---------- section component ---------- */
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl bg-zinc-900 border border-zinc-800 p-5">
      <h2 className="text-xs uppercase tracking-wider text-zinc-500 mb-4">
        {title}
      </h2>
      <div className="space-y-3">{children}</div>
    </div>
  );
}

/* ---------- field component ---------- */
function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-cyan-500 transition-colors"
      />
    </div>
  );
}

/* ---------- toggle component ---------- */
function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center justify-between cursor-pointer">
      <span className="text-sm text-zinc-300">{label}</span>
      <div
        onClick={() => onChange(!checked)}
        className={`relative w-9 h-5 rounded-full transition-colors ${checked ? "bg-cyan-600" : "bg-zinc-700"}`}
      >
        <div
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${checked ? "translate-x-4" : ""}`}
        />
      </div>
    </label>
  );
}

/* ---------- page ---------- */
export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings>({});
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  /* load settings */
  useEffect(() => {
    apiGet<Settings>("/api/settings").then((data) => {
      if (data) {
        setSettings(data);
        setLoaded(true);
      }
    });
  }, []);

  /* helper to update a field */
  const set = (key: string, value: unknown) =>
    setSettings((prev) => ({ ...prev, [key]: value }));

  /* save */
  const save = async () => {
    setSaving(true);
    const result = await apiPost<{ ok: boolean }>("/api/settings", settings);
    setSaving(false);
    if (result?.ok) {
      setToast({ type: "success", msg: "Settings saved" });
    } else {
      setToast({ type: "error", msg: "Failed to save settings" });
    }
    setTimeout(() => setToast(null), 3000);
  };

  if (!loaded) {
    return (
      <div className="flex items-center justify-center h-64">
        <span className="text-zinc-500 text-sm animate-pulse">
          Loading settings...
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Settings</h1>
        <button
          onClick={save}
          disabled={saving}
          className="rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 px-5 py-2 text-sm font-semibold text-white transition-colors"
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </div>

      {/* toast */}
      {toast && (
        <div
          className={`rounded-lg px-4 py-2 text-sm font-medium ${
            toast.type === "success"
              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
              : "bg-red-500/20 text-red-400 border border-red-500/30"
          }`}
        >
          {toast.msg}
        </div>
      )}

      {/* General */}
      <Section title="General">
        <Field
          label="Target URL"
          value={String(settings.target ?? "")}
          onChange={(v) => set("target", v)}
          placeholder="https://target.com"
        />
        <Field
          label="Max Concurrent Targets"
          value={String(settings.max_concurrent ?? "")}
          onChange={(v) => set("max_concurrent", parseInt(v, 10) || 0)}
          type="number"
        />
        <Field
          label="Scan Timeout (seconds)"
          value={String(settings.scan_timeout ?? "")}
          onChange={(v) => set("scan_timeout", parseInt(v, 10) || 0)}
          type="number"
        />
      </Section>

      {/* Stealth */}
      <Section title="Stealth">
        <Field
          label="Stealth Level (0-4)"
          value={String(settings.stealth_level ?? 0)}
          onChange={(v) => set("stealth_level", parseInt(v, 10) || 0)}
          type="number"
        />
        <Toggle
          label="WAF Evasion"
          checked={!!settings.waf_evasion}
          onChange={(v) => set("waf_evasion", v)}
        />
        <Toggle
          label="Randomize User-Agent"
          checked={!!settings.randomize_ua}
          onChange={(v) => set("randomize_ua", v)}
        />
      </Section>

      {/* Model Preferences */}
      <Section title="Model Preferences">
        <Field
          label="Deep Analysis Model"
          value={String(settings.model_deep ?? "")}
          onChange={(v) => set("model_deep", v)}
          placeholder="claude-opus"
        />
        <Field
          label="Fast Scanning Model"
          value={String(settings.model_fast ?? "")}
          onChange={(v) => set("model_fast", v)}
          placeholder="gemini-flash"
        />
        <Field
          label="Report Writing Model"
          value={String(settings.model_report ?? "")}
          onChange={(v) => set("model_report", v)}
          placeholder="claude-sonnet"
        />
      </Section>

      {/* Scan Intensity */}
      <Section title="Scan Intensity">
        <div>
          <label className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
            Intensity
          </label>
          <select
            value={String(settings.scan_intensity ?? "moderate")}
            onChange={(e) => set("scan_intensity", e.target.value)}
            className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="passive">Passive</option>
            <option value="light">Light</option>
            <option value="moderate">Moderate</option>
            <option value="aggressive">Aggressive</option>
          </select>
        </div>
        <Field
          label="Max Iterations"
          value={String(settings.max_iterations ?? "")}
          onChange={(v) => set("max_iterations", parseInt(v, 10) || 0)}
          type="number"
        />
        <Toggle
          label="Nuclei Scanner"
          checked={!!settings.nuclei_enabled}
          onChange={(v) => set("nuclei_enabled", v)}
        />
      </Section>

      {/* Notifications */}
      <Section title="Notifications">
        <Field
          label="Discord Webhook URL"
          value={String(settings.discord_webhook ?? "")}
          onChange={(v) => set("discord_webhook", v)}
          placeholder="https://discord.com/api/webhooks/..."
        />
        <Field
          label="Telegram Bot Token"
          value={String(settings.telegram_token ?? "")}
          onChange={(v) => set("telegram_token", v)}
          placeholder="123456:ABC-DEF..."
        />
        <Field
          label="Email SMTP"
          value={String(settings.email_smtp ?? "")}
          onChange={(v) => set("email_smtp", v)}
          placeholder="smtp.gmail.com:587"
        />
      </Section>
    </div>
  );
}
