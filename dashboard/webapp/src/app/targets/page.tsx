"use client";

import { useState, useMemo } from "react";
import { useApi } from "@/hooks/useApi";
import type { Target, Finding } from "@/lib/types";
import { Shield, ChevronRight, Globe } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { SearchInput } from "@/components/ui/SearchInput";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityPill } from "@/components/ui/SeverityPill";

function StatusDot({ status }: { status?: string }) {
  const tone =
    status === "active"   ? "var(--success)"
    : status === "scanning" ? "var(--brand)"
    : "var(--ink-4)";
  const animated = status === "scanning";
  return (
    <span
      className={`relative inline-block w-2 h-2 rounded-full ${animated ? "pulse-ring" : ""}`}
      style={{ background: tone }}
    />
  );
}

function TargetCard({
  target, onClick,
}: { target: Target; onClick: () => void }) {
  return (
    <Card
      hover
      onClick={onClick}
      className="cursor-pointer transition-all"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Globe size={14} style={{ color: "var(--ink-3)" }} />
          <div
            className="display"
            style={{
              fontSize: "1.05rem",
              color: "var(--ink-1)",
              fontFamily: "var(--font-geist-sans)",
            }}
          >
            {target.domain}
          </div>
        </div>
        <StatusDot status={target.status} />
      </div>

      <div className="flex items-center gap-3 text-xs mb-3" style={{ color: "var(--ink-3)" }}>
        {target.ip && (
          <span style={{ fontFamily: "var(--font-geist-mono)" }}>{target.ip}</span>
        )}
        {target.waf && (
          <span className="pill" style={{ background: "var(--brand-soft)", color: "var(--brand-ink)" }}>
            <Shield size={10} />
            {target.waf}
          </span>
        )}
      </div>

      {/* Tech chips */}
      <div className="flex flex-wrap gap-1.5 mb-4">
        {(target.technologies || []).slice(0, 6).map((tech) => (
          <span
            key={tech}
            className="pill"
            style={{
              background: "var(--surface-2)",
              color: "var(--ink-2)",
              fontSize: 10,
            }}
          >
            {tech}
          </span>
        ))}
        {(target.technologies?.length ?? 0) > 6 && (
          <span className="pill" style={{ background: "var(--surface-2)", color: "var(--ink-3)" }}>
            +{(target.technologies?.length ?? 0) - 6}
          </span>
        )}
      </div>

      <div
        className="flex items-center justify-between pt-3 text-xs"
        style={{ borderTop: "1px solid var(--border-1)", color: "var(--ink-3)" }}
      >
        <div className="flex items-center gap-3">
          <div>
            <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>
              {target.finding_count}
            </span>{" "}
            findings
          </div>
          {target.subdomain_count != null && (
            <div>
              <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>
                {target.subdomain_count}
              </span>{" "}
              subdomains
            </div>
          )}
          <div>
            <span style={{ color: "var(--ink-1)", fontWeight: 600 }}>
              {target.attack_count}
            </span>{" "}
            attacks
          </div>
        </div>
        <ChevronRight size={14} />
      </div>
    </Card>
  );
}

function TargetDrawer({
  target, onClose,
}: { target: Target | null; onClose: () => void }) {
  // Backend wraps the response in {findings:[...]}; accept both shapes.
  const { data: raw } = useApi<Finding[] | { findings: Finding[] }>(
    `target-findings-${target?.domain ?? ""}`,
    target
      ? `/api/findings?domain=${encodeURIComponent(target.domain)}&limit=50`
      : "",
    0,
  );
  const findings: Finding[] = Array.isArray(raw) ? raw : (raw?.findings ?? []);
  if (!target) return null;
  return (
    <>
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(20, 18, 14, 0.32)" }}
        onClick={onClose}
      />
      <aside
        className="fixed right-0 top-0 h-full w-[520px] z-50 overflow-y-auto fade-in"
        style={{
          background: "var(--surface-1)",
          borderLeft: "1px solid var(--border-1)",
          boxShadow: "var(--shadow-3)",
        }}
      >
        <div className="p-6">
          <div className="kicker">Target</div>
          <h2 className="display mt-1" style={{ fontSize: "1.5rem" }}>
            {target.domain}
          </h2>
          <div className="mt-1 text-xs" style={{ color: "var(--ink-3)", fontFamily: "var(--font-geist-mono)" }}>
            {target.ip}
          </div>

          <div className="mt-6 grid grid-cols-3 gap-4">
            <div>
              <div className="kicker">Findings</div>
              <div className="display" style={{ fontSize: "1.5rem" }}>
                {target.finding_count}
              </div>
            </div>
            <div>
              <div className="kicker">Subdomains</div>
              <div className="display" style={{ fontSize: "1.5rem" }}>
                {target.subdomain_count ?? "—"}
              </div>
            </div>
            <div>
              <div className="kicker">Attacks</div>
              <div className="display" style={{ fontSize: "1.5rem" }}>
                {target.attack_count}
              </div>
            </div>
          </div>

          {(findings ?? []).length > 0 && (
            <div className="mt-8">
              <div className="kicker mb-2">Recent findings</div>
              <div className="space-y-2">
                {(findings ?? []).slice(0, 12).map((f) => (
                  <div
                    key={f.id}
                    className="flex items-center gap-3 p-2 rounded-lg"
                    style={{ background: "var(--surface-2)" }}
                  >
                    <SeverityPill severity={f.severity as never} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm truncate" style={{ color: "var(--ink-1)" }}>
                        {f.title}
                      </div>
                      <div className="text-xs truncate" style={{ color: "var(--ink-3)", fontFamily: "var(--font-geist-mono)" }}>
                        {f.url}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

export default function TargetsPage() {
  const { data: targets } = useApi<Target[]>("targets", "/api/targets", 10000);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Target | null>(null);

  const filtered = useMemo(() => {
    if (!targets) return [];
    if (!search.trim()) return targets;
    const q = search.toLowerCase();
    return targets.filter(
      (t) =>
        t.domain.toLowerCase().includes(q) ||
        t.technologies?.some((x) => x.toLowerCase().includes(q)),
    );
  }, [targets, search]);

  return (
    <div>
      <PageHeader
        kicker="Reach"
        title="Targets"
        subtitle={
          targets
            ? `${targets.length} targets · ${filtered.length} shown`
            : "Loading…"
        }
        actions={
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Domain or technology…"
          />
        }
      />

      {filtered.length === 0 ? (
        <EmptyState
          title="No targets yet"
          hint="Targets appear here after a hunt or recon job discovers them."
          icon={<Globe size={20} />}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((t) => (
            <TargetCard
              key={t.id}
              target={t}
              onClick={() => setSelected(t)}
            />
          ))}
        </div>
      )}

      <TargetDrawer target={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
