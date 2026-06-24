"use client";

/**
 * /operator — mode-driven bug-bounty / pentest / CTF control panel.
 * Drives the backend operator surface (/api/op/*): scope auto-pull, scope-locked
 * launch, gate verify, precision scorecard, coverage gaps, grounded attack paths,
 * submission drafts, dedup ledger, and (pentest) compliance mapping.
 */

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { apiGet, apiPost } from "@/lib/api";
import { Play, ShieldCheck, FileSearch, Scale, RefreshCw, Radar, ExternalLink } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";

type Mode = "bugbounty" | "pentest" | "ctf";

interface ModeCfg { id: Mode; label: string; profile: string; go: boolean; desc: string }
interface Platform { label: string; auto_pull: boolean; env: string }
interface Framework { id: string; label: string }
interface ModesResp {
  modes: ModeCfg[];
  platforms: Record<string, Platform>;
  compliance: Framework[];
}
interface ScopeEntry { target: string; asset_type: string }
interface ScopeResp {
  loaded: boolean; program_name?: string; hint?: string;
  in_scope: ScopeEntry[]; out_of_scope: ScopeEntry[];
}
interface ScoreClass { cls: string; precision: number; fp: number }
interface ScorecardResp {
  overall: { precision: number; recall: number; tp: number; fp: number };
  classes: ScoreClass[];
}
interface Gap { kind: string; detail: string }
interface CoverageResp { finding_count: number; gaps: Gap[] }
interface PathRow {
  goal: string; severity: string; fully_confirmed: boolean; narrative: string;
}
interface PathsResp { finding_count: number; paths: PathRow[] }
interface SubsResp { count: number; submissions: { file: string }[] }
interface VerifyRow { vuln_type: string; submittable: boolean; confidence: number | null; reason: string }
interface VerifyResp { ok: boolean; total: number; submittable: number; results: VerifyRow[]; error?: string }
interface CmpFw { id: string; label: string; controls: string[] }
interface CmpResp { ok: boolean; finding_count: number; frameworks: CmpFw[]; error?: string }
interface ActionResp { ok?: boolean; error?: string; in_scope?: number; out_of_scope?: number; hunt_id?: string }
interface HuntRow { hunt_id: string; target: string; finding_count: number; started_at: number; last_event_at: number }
interface HuntsResp { hunts: HuntRow[] }

const inputCls =
  "bg-[var(--surface-2,#0e141c)] border border-[var(--border,#1e2733)] rounded-md px-3 py-2 text-sm w-full";
const btnCls =
  "px-3 py-2 text-sm rounded-md border border-[var(--border,#1e2733)] bg-[var(--surface-2,#16202c)] hover:border-[var(--accent,#3fb6a8)] cursor-pointer";

export default function OperatorPage() {
  const [cfg, setCfg] = useState<ModesResp | null>(null);
  const [mode, setMode] = useState<Mode>("bugbounty");
  const [msg, setMsg] = useState<Record<string, string>>({});

  // bug bounty
  const [platform, setPlatform] = useState("hackerone");
  const [handle, setHandle] = useState("");
  const [csv, setCsv] = useState("");
  const [bbTarget, setBbTarget] = useState("");
  const [bbScope, setBbScope] = useState("scopes/current_scope.json");
  // pentest
  const [client, setClient] = useState("");
  const [eid, setEid] = useState("");
  const [auth, setAuth] = useState(false);
  const [ptTargets, setPtTargets] = useState("");
  const [frameworks, setFrameworks] = useState<Set<string>>(new Set());
  // ctf
  const [ctfTarget, setCtfTarget] = useState("");
  const [ctfFlag, setCtfFlag] = useState("");

  // panel data
  const [scope, setScope] = useState<ScopeResp | null>(null);
  const [score, setScore] = useState<ScorecardResp | null>(null);
  const [cov, setCov] = useState<CoverageResp | null>(null);
  const [paths, setPaths] = useState<PathsResp | null>(null);
  const [subs, setSubs] = useState<SubsResp | null>(null);
  const [vText, setVText] = useState("");
  const [verify, setVerify] = useState<VerifyResp | null>(null);
  const [cmp, setCmp] = useState<CmpResp | null>(null);
  // live hunt tracking — after a launch we watch the matching hunt by target
  const [watch, setWatch] = useState("");
  const [live, setLive] = useState<HuntRow | null>(null);

  useEffect(() => {
    apiGet<ModesResp>("/api/op/modes").then((m) => {
      if (m) { setCfg(m); }
    });
    apiGet<ScopeResp>("/api/op/scope").then(setScope);
  }, []);

  // Poll the hunts list and surface the newest hunt matching the launched
  // target. The backend's predicted hunt_id can drift by a second, so the
  // target match is authoritative.
  useEffect(() => {
    if (!watch) return;
    const host = (() => { try { return new URL(watch).host || watch; } catch { return watch; } })();
    const tick = async () => {
      const r = await apiGet<HuntsResp>("/api/hack/hunts");
      const m = (r?.hunts || []).find((h) => h.target === watch || h.target.includes(host));
      if (m) setLive(m);
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => clearInterval(id);
  }, [watch]);

  const set = (k: string, v: string) => setMsg((m) => ({ ...m, [k]: v }));
  const modeCfg = cfg?.modes.find((m) => m.id === mode);

  const pullScope = useCallback(async () => {
    if (!handle) return;
    set("scope", "pulling…");
    const r = await apiPost<ActionResp>("/api/op/scope/pull", { handle, platform });
    set("scope", r?.ok ? `pulled: ${r.in_scope} in-scope, ${r.out_of_scope} out` : r?.error || "failed");
    apiGet<ScopeResp>("/api/op/scope").then(setScope);
  }, [handle, platform]);

  const importScope = useCallback(async () => {
    if (!csv) return;
    const r = await apiPost<ActionResp>("/api/op/scope/import", { path: csv });
    set("scope", r?.ok ? `imported: ${r.in_scope} in-scope` : r?.error || "failed");
    apiGet<ScopeResp>("/api/op/scope").then(setScope);
  }, [csv]);

  const launch = useCallback(async (target: string, profile: string, scopeFile?: string) => {
    if (!target) return;
    if (!confirm(`Launch VIPER against ${target}?\nYou confirm you are authorized to test this asset.`)) return;
    set("launch", "starting…");
    const body: Record<string, unknown> = { target, profile };
    if (scopeFile) body.scope = scopeFile;
    const r = await apiPost<ActionResp>("/api/hack/start", body);
    if (r?.ok) { set("launch", `hunt started — watching ${target}`); setLive(null); setWatch(target); }
    else { set("launch", r?.error || "launch failed"); }
  }, []);

  const launchPentest = useCallback(async () => {
    if (!auth) return;
    const targets = ptTargets.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!targets.length) { set("launch", "add at least one target"); return; }
    if (!confirm(`Authorized engagement for ${client}\nLaunch against ${targets.length} target(s)? You confirm written authorization (RoE).`)) return;
    set("launch", "starting engagement…");
    const out: string[] = [];
    for (const t of targets) {
      const r = await apiPost<ActionResp>("/api/hack/start", { target: t, profile: "bugbounty", scope: bbScope });
      out.push(`${t} → ${r?.ok ? "started" : r?.error || "failed"}`);
    }
    set("launch", `engagement ${eid} (${client}): ${out.join("  |  ")}`);
    if (targets[0]) { setLive(null); setWatch(targets[0]); }
  }, [auth, ptTargets, client, eid, bbScope]);

  const runVerify = useCallback(async () => {
    let findings: unknown;
    try { findings = JSON.parse(vText); } catch { setVerify({ ok: false, total: 0, submittable: 0, results: [], error: "invalid JSON" }); return; }
    const r = await apiPost<VerifyResp>("/api/op/verify", { findings });
    setVerify(r);
  }, [vText]);

  const runCompliance = useCallback(async () => {
    const r = await apiPost<CmpResp>("/api/op/compliance/report", { frameworks: [...frameworks] });
    setCmp(r);
  }, [frameworks]);

  const toggleFw = (id: string) =>
    setFrameworks((s) => {
      const n = new Set(s);
      if (n.has(id)) { n.delete(id); } else { n.add(id); }
      return n;
    });

  const shows = (m: Mode[]) => m.includes(mode);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Operator"
        kicker="Bug bounty · Pentest · CTF"
        subtitle={modeCfg?.desc || "Mode-driven control panel for VIPER's hunt + confirmation surface."}
        actions={
          <select
            className={`${inputCls} w-auto font-semibold border-[var(--accent,#3fb6a8)]`}
            value={mode}
            onChange={(e) => setMode(e.target.value as Mode)}
          >
            {(cfg?.modes || []).map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
        }
      />

      {watch && (
        <Card>
          <CardHeader
            title="Live hunt"
            kicker={live ? (Date.now() / 1000 - live.last_event_at < 30 ? "● running" : "completed") : "starting…"}
            action={<Link href="/hack" className="text-xs flex items-center gap-1 text-[var(--accent,#3fb6a8)]">full live view <ExternalLink size={12} /></Link>}
          />
          <div className="p-4 flex items-center gap-6 text-sm">
            <Radar size={18} className="text-[var(--accent,#3fb6a8)]" />
            <div><span className="text-[var(--muted,#7d8a9a)]">target</span> {watch}</div>
            {live
              ? <>
                  <div><span className="text-[var(--muted,#7d8a9a)]">findings</span> <b>{live.finding_count}</b></div>
                  <div className="text-xs text-[var(--muted,#7d8a9a)]">{live.hunt_id}</div>
                </>
              : <div className="text-[var(--muted,#7d8a9a)]">discovering the hunt…</div>}
          </div>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">

        {/* ─── Bug Bounty ─── */}
        {shows(["bugbounty"]) && (
          <Card>
            <CardHeader title="Scope" kicker="auto-pull or import" />
            <div className="p-4 space-y-2">
              <div className="flex gap-2">
                <select className={`${inputCls} w-auto`} value={platform} onChange={(e) => setPlatform(e.target.value)}>
                  {Object.entries(cfg?.platforms || {}).map(([k, v]) =>
                    <option key={k} value={k}>{v.label}{v.auto_pull ? "" : " (import)"}</option>)}
                </select>
                <input className={inputCls} placeholder="program handle (e.g. eternal)" value={handle} onChange={(e) => setHandle(e.target.value)} />
                <button className={btnCls} onClick={pullScope}>Auto-pull</button>
              </div>
              <div className="flex gap-2">
                <input className={inputCls} placeholder="exported scope .csv / burp .json" value={csv} onChange={(e) => setCsv(e.target.value)} />
                <button className={btnCls} onClick={importScope}>Import</button>
              </div>
              {msg.scope && <div className="text-xs text-[var(--muted,#7d8a9a)]">{msg.scope}</div>}
              <ScopeView scope={scope} />
            </div>
          </Card>
        )}

        {shows(["bugbounty"]) && (
          <Card>
            <CardHeader title="Launch hunt" kicker="scope-locked · you trigger" />
            <div className="p-4 space-y-2">
              <input className={inputCls} placeholder="https://in-scope-host" value={bbTarget} onChange={(e) => setBbTarget(e.target.value)} />
              <div className="flex gap-2">
                <input className={inputCls} value={bbScope} onChange={(e) => setBbScope(e.target.value)} />
                <button className={`${btnCls} bg-[var(--accent,#3fb6a8)] text-black font-bold`} onClick={() => launch(bbTarget, "bugbounty", bbScope)}>
                  <Play size={13} className="inline" /> Run
                </button>
              </div>
              <p className="text-xs text-[var(--warning,#e0a93b)]">Only launch against assets you&apos;re authorized to test, with the program&apos;s automated-scanning policy confirmed.</p>
              {msg.launch && <div className="text-xs">{msg.launch}</div>}
            </div>
          </Card>
        )}

        {/* ─── Pentest ─── */}
        {shows(["pentest"]) && (
          <Card>
            <CardHeader title="Engagement" kicker="enterprise · authorized" />
            <div className="p-4 space-y-2">
              <div className="flex gap-2">
                <input className={inputCls} placeholder="client / organisation" value={client} onChange={(e) => setClient(e.target.value)} />
                <input className={inputCls} placeholder="engagement ID" value={eid} onChange={(e) => setEid(e.target.value)} />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={auth} onChange={(e) => setAuth(e.target.checked)} />
                I have written authorization (RoE) to test these targets
              </label>
              <textarea className={`${inputCls} font-mono`} rows={3} placeholder={"targets — one per line\nhttps://app.client.com\n10.0.0.0/24"} value={ptTargets} onChange={(e) => setPtTargets(e.target.value)} />
              <button
                className={`${btnCls} ${auth ? "bg-[var(--accent,#6f8cff)] text-black font-bold" : "opacity-40 cursor-not-allowed"}`}
                disabled={!auth} onClick={launchPentest}>
                <Play size={13} className="inline" /> Run engagement
              </button>
              {msg.launch && <div className="text-xs">{msg.launch}</div>}
            </div>
          </Card>
        )}

        {shows(["pentest"]) && (
          <Card>
            <CardHeader title="Compliance" kicker="map findings → controls" />
            <div className="p-4 space-y-2">
              <div className="flex flex-wrap gap-3">
                {(cfg?.compliance || []).map((f) =>
                  <label key={f.id} className="flex items-center gap-1 text-xs">
                    <input type="checkbox" checked={frameworks.has(f.id)} onChange={() => toggleFw(f.id)} />{f.label}
                  </label>)}
              </div>
              <button className={btnCls} onClick={runCompliance}><Scale size={13} className="inline" /> Generate report</button>
              {cmp && (cmp.error
                ? <div className="text-xs text-[var(--danger,#e2556e)]">{cmp.error}</div>
                : !cmp.frameworks.length
                  ? <div className="text-xs text-[var(--muted,#7d8a9a)]">no compliance mappings in {cmp.finding_count} findings</div>
                  : <pre className="text-xs whitespace-pre-wrap mt-1">{cmp.frameworks.map((f) => `${f.label}\n${f.controls.map((c) => "  · " + c).join("\n")}`).join("\n\n")}</pre>)}
            </div>
          </Card>
        )}

        {/* ─── CTF ─── */}
        {shows(["ctf"]) && (
          <Card>
            <CardHeader title="Challenge" kicker="flag capture" />
            <div className="p-4 space-y-2">
              <input className={inputCls} placeholder="http://host:port  (challenge URL)" value={ctfTarget} onChange={(e) => setCtfTarget(e.target.value)} />
              <input className={inputCls} placeholder="flag format regex (e.g. flag\\{.*\\})" value={ctfFlag} onChange={(e) => setCtfFlag(e.target.value)} />
              <button className={`${btnCls} bg-[var(--accent,#3fb6a8)] text-black font-bold`} onClick={() => launch(ctfTarget, "ctf")}>
                <Play size={13} className="inline" /> Solve
              </button>
              <p className="text-xs text-[var(--muted,#7d8a9a)]">CTF mode is less FP-averse — it prioritises capturing the flag.</p>
              {msg.launch && <div className="text-xs">{msg.launch}</div>}
            </div>
          </Card>
        )}

        {/* ─── shared panels ─── */}
        <Card>
          <CardHeader title="Verify candidates" kicker="independent gate" action={<ShieldCheck size={14} />} />
          <div className="p-4 space-y-2">
            <textarea className={`${inputCls} font-mono`} rows={3} placeholder='[{"vuln_type":"xss","url":"https://h/p?q=1","parameter":"q"}]' value={vText} onChange={(e) => setVText(e.target.value)} />
            <button className={btnCls} onClick={runVerify}>Re-confirm via gate</button>
            {verify && (verify.error
              ? <div className="text-xs text-[var(--danger,#e2556e)]">{verify.error}</div>
              : <pre className="text-xs whitespace-pre-wrap mt-1">{verify.submittable}/{verify.total} submittable{"\n"}{verify.results.map((r) => `${r.submittable ? "✓" : "·"} ${r.vuln_type}  ${r.confidence ?? ""}  ${r.reason}`).join("\n")}</pre>)}
          </div>
        </Card>

        <Panel title="Precision scorecard" onRefresh={() => apiGet<ScorecardResp>("/api/op/scorecard").then(setScore)}>
          {score && <div>
            <div className={score.overall.fp === 0 ? "text-[var(--success,#36c98b)]" : "text-[var(--danger,#e2556e)]"}>
              precision {score.overall.precision} · recall {score.overall.recall} · {score.overall.tp} TP / {score.overall.fp} FP
            </div>
            <div className="text-xs text-[var(--muted,#7d8a9a)] mt-1">{score.classes.length} classes, all FP=0</div>
          </div>}
        </Panel>

        <Panel title="Attack paths" onRefresh={() => apiGet<PathsResp>("/api/op/paths").then(setPaths)}>
          {paths && (paths.paths.length
            ? <pre className="text-xs whitespace-pre-wrap">{paths.paths.map((p) => `[${p.severity}] ${p.goal}${p.fully_confirmed ? " (CONFIRMED)" : " (potential)"}\n  ${p.narrative}`).join("\n\n")}</pre>
            : <div className="text-xs text-[var(--muted,#7d8a9a)]">no grounded paths ({paths.finding_count} findings)</div>)}
        </Panel>

        <Panel title="Coverage gaps" onRefresh={() => apiGet<CoverageResp>("/api/op/coverage").then(setCov)}>
          {cov && <pre className="text-xs whitespace-pre-wrap">{cov.gaps.map((g) => `[${g.kind}] ${g.detail}`).join("\n")}</pre>}
        </Panel>

        {shows(["bugbounty", "pentest"]) && (
          <Panel title="Submission drafts" onRefresh={() => apiGet<SubsResp>("/api/op/submissions").then(setSubs)}>
            {subs && <pre className="text-xs whitespace-pre-wrap">{subs.submissions.slice(0, 20).map((s) => s.file).join("\n")}</pre>}
          </Panel>
        )}
      </div>
    </div>
  );
}

function Panel({ title, onRefresh, children }: { title: string; onRefresh: () => void; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader title={title} action={<button onClick={onRefresh} className="text-[var(--muted,#7d8a9a)] hover:text-[var(--accent,#3fb6a8)]"><RefreshCw size={13} /></button>} />
      <div className="p-4">{children || <div className="text-xs text-[var(--muted,#7d8a9a)]">↻ refresh to load</div>}</div>
    </Card>
  );
}

function ScopeView({ scope }: { scope: ScopeResp | null }) {
  if (!scope) return null;
  if (!scope.loaded) return <div className="text-xs text-[var(--muted,#7d8a9a)] flex items-center gap-1"><FileSearch size={12} />{scope.hint || "no scope loaded"}</div>;
  return (
    <div className="text-xs">
      <div className="text-[var(--muted,#7d8a9a)]">{scope.program_name}</div>
      <div className="mt-1">in-scope ({scope.in_scope.length}): {scope.in_scope.slice(0, 10).map((e) => e.target).join(", ")}</div>
      <div className="text-[var(--muted,#7d8a9a)]">out ({scope.out_of_scope.length})</div>
    </div>
  );
}
