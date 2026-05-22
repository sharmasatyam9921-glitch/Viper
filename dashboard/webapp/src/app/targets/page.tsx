"use client";

import { useState } from "react";
import { useApi } from "@/hooks/useApi";
import type { Target, Finding } from "@/lib/types";

/* ---------- status dot ---------- */
function StatusDot({ status }: { status?: string }) {
  const color =
    status === "active"
      ? "bg-emerald-400"
      : status === "scanning"
        ? "bg-cyan-400 animate-pulse"
        : "bg-zinc-600";
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
}

/* ---------- target card ---------- */
function TargetCard({
  target,
  onClick,
}: {
  target: Target;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className="rounded-xl bg-zinc-900 border border-zinc-800 p-5 hover:border-zinc-600 cursor-pointer transition-colors"
    >
      <div className="flex items-center gap-2 mb-3">
        <StatusDot status={target.status} />
        <h3 className="text-sm font-bold text-zinc-100 truncate">
          {target.domain}
        </h3>
      </div>

      {target.ip && (
        <p className="text-xs text-zinc-500 font-mono mb-3">{target.ip}</p>
      )}

      {/* tech pills */}
      {target.technologies.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {target.technologies.slice(0, 6).map((t) => (
            <span
              key={t}
              className="rounded-full bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400"
            >
              {t}
            </span>
          ))}
          {target.technologies.length > 6 && (
            <span className="text-[10px] text-zinc-600 self-center">
              +{target.technologies.length - 6}
            </span>
          )}
        </div>
      )}

      {/* stats row */}
      <div className="flex gap-4 text-xs text-zinc-500">
        <span>
          <strong className="text-zinc-300">{target.finding_count}</strong>{" "}
          findings
        </span>
        <span>
          <strong className="text-zinc-300">{target.attack_count}</strong>{" "}
          attacks
        </span>
        {target.subdomain_count != null && (
          <span>
            <strong className="text-zinc-300">{target.subdomain_count}</strong>{" "}
            subs
          </span>
        )}
      </div>

      {target.last_scanned && (
        <p className="text-[10px] text-zinc-600 mt-2">
          Last scanned: {target.last_scanned}
        </p>
      )}
    </div>
  );
}

/* ---------- detail panel ---------- */
function DetailPanel({
  target,
  onClose,
}: {
  target: Target;
  onClose: () => void;
}) {
  const { data: findings } = useApi<{ findings: Finding[] }>(
    `target-findings-${target.id}`,
    `/api/findings?domain=${encodeURIComponent(target.domain)}&limit=50`,
  );

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-[520px] bg-zinc-900 border-l border-zinc-700 shadow-2xl flex flex-col">
      <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
        <div>
          <h2 className="text-sm font-bold text-zinc-100">{target.domain}</h2>
          {target.ip && (
            <p className="text-xs text-zinc-500 font-mono">{target.ip}</p>
          )}
        </div>
        <button
          onClick={onClose}
          className="text-zinc-500 hover:text-zinc-300 text-lg leading-none"
        >
          &times;
        </button>
      </div>

      {/* tech stack */}
      {target.technologies.length > 0 && (
        <div className="px-5 py-3 border-b border-zinc-800">
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2">
            Technologies
          </p>
          <div className="flex flex-wrap gap-1.5">
            {target.technologies.map((t) => (
              <span
                key={t}
                className="rounded-full bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-300"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* waf & status */}
      <div className="px-5 py-3 border-b border-zinc-800 flex gap-6 text-xs text-zinc-400">
        {target.waf && (
          <span>
            WAF: <strong className="text-zinc-200">{target.waf}</strong>
          </span>
        )}
        <span>
          Status:{" "}
          <strong className="text-zinc-200">{target.status ?? "idle"}</strong>
        </span>
      </div>

      {/* findings list */}
      <div className="flex-1 overflow-y-auto p-5">
        <p className="text-xs text-zinc-500 uppercase tracking-wider mb-3">
          Findings ({findings?.findings?.length ?? 0})
        </p>
        <div className="space-y-2">
          {(findings?.findings ?? []).map((f) => (
            <div
              key={f.id}
              className="rounded-lg bg-zinc-950 border border-zinc-800 p-3"
            >
              <div className="flex items-center gap-2 mb-1">
                <SevDot severity={f.severity} />
                <span className="text-xs font-medium text-zinc-200 truncate">
                  {f.title}
                </span>
              </div>
              <p className="text-[10px] text-zinc-500 font-mono truncate">
                {f.url}
              </p>
            </div>
          ))}
          {(!findings || findings.findings.length === 0) && (
            <p className="text-xs text-zinc-600">
              No findings for this target.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function SevDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-zinc-500",
  };
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${colors[severity] ?? colors.info}`}
    />
  );
}

/* ---------- page ---------- */
export default function TargetsPage() {
  const { data: targets } = useApi<Target[]>("targets", "/api/targets", 10000);
  const [selected, setSelected] = useState<Target | null>(null);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-zinc-100">Targets</h1>

      <div className="grid grid-cols-3 gap-4">
        {(targets ?? []).map((t) => (
          <TargetCard
            key={t.id}
            target={t}
            onClick={() => setSelected(t)}
          />
        ))}
        {(!targets || targets.length === 0) && (
          <p className="col-span-3 text-center text-zinc-600 py-12">
            No targets yet. Start a hunt to add targets.
          </p>
        )}
      </div>

      {/* detail panel */}
      {selected && (
        <>
          <div
            className="fixed inset-0 bg-black/40 z-40"
            onClick={() => setSelected(null)}
          />
          <DetailPanel
            target={selected}
            onClose={() => setSelected(null)}
          />
        </>
      )}
    </div>
  );
}
