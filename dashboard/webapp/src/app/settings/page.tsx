"use client";

import { useState, useEffect } from "react";
import { apiGet, apiPost } from "@/lib/api";
import { Settings as SettingsIcon, Save, Check, X } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";

interface Settings {
  target?: string;
  max_concurrent?: number;
  scan_timeout?: number;
  stealth_level?: number;
  waf_evasion?: boolean;
  randomize_ua?: boolean;
  model_deep?: string;
  model_fast?: string;
  model_report?: string;
  scan_intensity?: string;
  max_iterations?: number;
  nuclei_enabled?: boolean;
  discord_webhook?: string;
  telegram_token?: string;
  telegram_chat?: string;
  smtp_host?: string;
  smtp_port?: number;
  smtp_user?: string;
  smtp_password?: string;
  hackerone_token?: string;
  rate_limit?: number;
}

function Field({
  label, hint, children,
}: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block">
        <div className="text-sm font-medium mb-1.5" style={{ color: "var(--ink-1)" }}>
          {label}
        </div>
        {children}
        {hint && (
          <div className="text-xs mt-1" style={{ color: "var(--ink-3)" }}>
            {hint}
          </div>
        )}
      </label>
    </div>
  );
}

function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className="w-full px-3 py-2 rounded-lg outline-none text-sm transition-shadow"
      style={{
        background: "var(--surface-2)",
        border: "1px solid var(--border-1)",
        color: "var(--ink-1)",
        fontFamily: props.type === "password" || props.type === "url" ? "var(--font-geist-mono)" : undefined,
        ...props.style,
      }}
    />
  );
}

function Toggle({
  checked, onChange, label,
}: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center justify-between cursor-pointer py-1.5">
      <span className="text-sm" style={{ color: "var(--ink-1)" }}>{label}</span>
      <button
        onClick={() => onChange(!checked)}
        className="relative w-10 h-5 rounded-full transition-colors"
        style={{ background: checked ? "var(--brand)" : "var(--surface-3)" }}
      >
        <span
          className="absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform"
          style={{ transform: checked ? "translateX(20px)" : "none" }}
        />
      </button>
    </label>
  );
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings>({});
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  useEffect(() => {
    apiGet<Settings>("/api/settings").then((d) => { if (d) { setSettings(d); setLoaded(true); } });
  }, []);

  const set = (k: keyof Settings, v: unknown) => setSettings((p) => ({ ...p, [k]: v }));

  const save = async () => {
    setSaving(true);
    const r = await apiPost<{ ok: boolean }>(
      "/api/settings",
      settings as unknown as Record<string, unknown>,
    );
    setSaving(false);
    setToast(r?.ok
      ? { type: "success", msg: "Settings saved" }
      : { type: "error", msg: "Failed to save" });
    setTimeout(() => setToast(null), 3000);
  };

  if (!loaded) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="skeleton" style={{ width: 200, height: 12 }} />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        kicker="Configuration"
        title="Settings"
        subtitle="Engine, models, stealth, notifications, integrations."
        actions={
          <button onClick={save} disabled={saving} className="btn-primary">
            <Save size={13} />
            {saving ? "Saving" : "Save"}
          </button>
        }
      />

      {toast && (
        <div
          className="fade-in pill"
          style={{
            background: toast.type === "success" ? "var(--success-soft)" : "var(--critical-soft)",
            color: toast.type === "success" ? "var(--success)" : "var(--critical)",
            position: "fixed",
            bottom: 24,
            right: 24,
            padding: "8px 14px",
            boxShadow: "var(--shadow-2)",
            zIndex: 60,
          }}
        >
          {toast.type === "success" ? <Check size={12} /> : <X size={12} />}
          {toast.msg}
        </div>
      )}

      {/* General */}
      <Card padding="none">
        <CardHeader title="General" kicker="Engine" />
        <div className="p-5 grid grid-cols-2 gap-4">
          <Field label="Target">
            <TextInput
              type="url"
              value={settings.target ?? ""}
              onChange={(e) => set("target", e.target.value)}
              placeholder="https://target.example.com"
            />
          </Field>
          <Field label="Max concurrent" hint="Parallel scan workers">
            <TextInput
              type="number"
              value={settings.max_concurrent ?? 4}
              onChange={(e) => set("max_concurrent", parseInt(e.target.value) || 4)}
            />
          </Field>
          <Field label="Scan timeout (s)">
            <TextInput
              type="number"
              value={settings.scan_timeout ?? 60}
              onChange={(e) => set("scan_timeout", parseInt(e.target.value) || 60)}
            />
          </Field>
          <Field label="Rate limit (req/s)">
            <TextInput
              type="number"
              value={settings.rate_limit ?? 10}
              onChange={(e) => set("rate_limit", parseInt(e.target.value) || 10)}
            />
          </Field>
        </div>
      </Card>

      {/* Stealth */}
      <Card padding="none">
        <CardHeader title="Stealth" kicker="Evasion" />
        <div className="p-5 space-y-2">
          <Field label="Stealth level (0-4)">
            <TextInput
              type="number"
              min={0}
              max={4}
              value={settings.stealth_level ?? 0}
              onChange={(e) => set("stealth_level", parseInt(e.target.value))}
            />
          </Field>
          <Toggle
            label="WAF evasion"
            checked={!!settings.waf_evasion}
            onChange={(v) => set("waf_evasion", v)}
          />
          <Toggle
            label="Randomize User-Agent"
            checked={!!settings.randomize_ua}
            onChange={(v) => set("randomize_ua", v)}
          />
        </div>
      </Card>

      {/* Models */}
      <Card padding="none">
        <CardHeader title="LLM models" kicker="Routing" />
        <div className="p-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Field label="Deep think" hint="anthropic/claude-opus-4-5">
            <TextInput value={settings.model_deep ?? ""} onChange={(e) => set("model_deep", e.target.value)} />
          </Field>
          <Field label="Fast triage" hint="gemini/gemini-flash-1.5">
            <TextInput value={settings.model_fast ?? ""} onChange={(e) => set("model_fast", e.target.value)} />
          </Field>
          <Field label="Reports">
            <TextInput value={settings.model_report ?? ""} onChange={(e) => set("model_report", e.target.value)} />
          </Field>
        </div>
      </Card>

      {/* Notifications */}
      <Card padding="none">
        <CardHeader title="Notifications" kicker="Outbound" />
        <div className="p-5 space-y-3">
          <Field label="Discord webhook" hint="Empty disables Discord notifications">
            <TextInput
              type="url"
              placeholder="https://discord.com/api/webhooks/…"
              value={settings.discord_webhook ?? ""}
              onChange={(e) => set("discord_webhook", e.target.value)}
            />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Telegram bot token">
              <TextInput
                type="password"
                value={settings.telegram_token ?? ""}
                onChange={(e) => set("telegram_token", e.target.value)}
              />
            </Field>
            <Field label="Telegram chat ID">
              <TextInput
                value={settings.telegram_chat ?? ""}
                onChange={(e) => set("telegram_chat", e.target.value)}
              />
            </Field>
          </div>
        </div>
      </Card>

      {/* Integrations */}
      <Card padding="none">
        <CardHeader title="Integrations" kicker="Submission" />
        <div className="p-5">
          <Field label="HackerOne API token" hint="Only used when --submit is passed; never auto-submitted">
            <TextInput
              type="password"
              value={settings.hackerone_token ?? ""}
              onChange={(e) => set("hackerone_token", e.target.value)}
            />
          </Field>
        </div>
      </Card>
    </div>
  );
}
