"use client";

import { useState, useRef, useEffect } from "react";
import { useApi } from "@/hooks/useApi";
import { apiGet, apiPost } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { Wrench, GitPullRequest, CheckCircle, AlertCircle, Loader } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityPill } from "@/components/ui/SeverityPill";

interface FixStatus {
  finding_id: number;
  status: "pending" | "running" | "completed" | "failed";
  message?: string;
  pr_url?: string;
}
interface TriageFinding extends Finding {
  priority_score?: number;
}

function StatusBadge({ status }: { status: string }) {
  const map = {
    pending:   { bg: "var(--surface-2)",     fg: "var(--ink-3)",    icon: null },
    running:   { bg: "var(--brand-soft)",    fg: "var(--brand)",    icon: <Loader size={11} className="animate-spin" /> },
    completed: { bg: "var(--success-soft)",  fg: "var(--success)",  icon: <CheckCircle size={11} /> },
    failed:    { bg: "var(--critical-soft)", fg: "var(--critical)", icon: <AlertCircle size={11} /> },
  };
  const t = map[status as keyof typeof map] ?? map.pending;
  return (
    <span className="pill" style={{ background: t.bg, color: t.fg }}>
      {t.icon}
      <span style={{ textTransform: "capitalize" }}>{status}</span>
    </span>
  );
}

export default function CypherFixPage() {
  // Backend wraps the response in {findings: [...]}; accept both shapes.
  const { data: raw } = useApi<TriageFinding[] | { findings: TriageFinding[] }>(
    "triage-findings", "/api/triage/findings", 5000);
  const findings: TriageFinding[] | undefined = Array.isArray(raw)
    ? raw
    : raw?.findings;
  const [statuses, setStatuses] = useState<Record<number, FixStatus>>({});
  // Track every live poll interval by finding id so we can clear them on
  // unmount (otherwise navigating away leaks the timer and calls setState on
  // an unmounted component) and avoid stacking two polls on the same fix.
  const intervalsRef = useRef<Map<number, ReturnType<typeof setInterval>>>(new Map());

  const stopPoll = (id: number) => {
    const handle = intervalsRef.current.get(id);
    if (handle !== undefined) {
      clearInterval(handle);
      intervalsRef.current.delete(id);
    }
  };

  // Clear all outstanding polls when the page unmounts.
  useEffect(() => {
    const intervals = intervalsRef.current;
    return () => {
      intervals.forEach((h) => clearInterval(h));
      intervals.clear();
    };
  }, []);

  const startFix = async (id: number) => {
    stopPoll(id); // never run two polls for the same finding
    setStatuses((p) => ({ ...p, [id]: { finding_id: id, status: "running" } }));
    const r = await apiPost<{ job_id: string }>("/api/codefix/run", { finding_id: id });
    if (!r) {
      setStatuses((p) => ({ ...p, [id]: { finding_id: id, status: "failed", message: "Failed to start" } }));
      return;
    }
    const poll = setInterval(async () => {
      const s = await apiGet<FixStatus>(`/api/codefix/status?finding_id=${id}`);
      if (s) {
        setStatuses((p) => ({ ...p, [id]: s }));
        if (s.status === "completed" || s.status === "failed") {
          stopPoll(id);
        }
      }
    }, 2000);
    intervalsRef.current.set(id, poll);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Remediation"
        title="CypherFix"
        subtitle="Tree-sitter-aware ReACT fix loop — generates PRs that patch the vulnerable code."
        actions={
          <div className="text-xs" style={{ color: "var(--ink-3)" }}>
            {findings?.length ?? 0} findings prioritized for remediation
          </div>
        }
      />

      {(!findings || findings.length === 0) ? (
        <EmptyState
          title="Nothing to triage"
          hint="Findings appear here once VIPER has scored them. Run a hunt first."
          icon={<Wrench size={20} />}
        />
      ) : (
        <div className="space-y-3">
          {findings.map((f) => {
            const status = statuses[f.id];
            return (
              <Card key={f.id} className="transition-all">
                <div className="flex items-center gap-4 flex-wrap">
                  <SeverityPill severity={f.severity as never} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate" style={{ color: "var(--ink-1)" }}>
                      {f.title}
                    </div>
                    <div className="text-xs mt-0.5 flex items-center gap-2 flex-wrap" style={{ color: "var(--ink-3)" }}>
                      <span style={{
                        fontFamily: "var(--font-geist-mono)",
                        background: "var(--surface-2)",
                        padding: "1px 6px",
                        borderRadius: 4,
                      }}>
                        {f.vuln_type}
                      </span>
                      {f.cwe && (
                        <span style={{ fontFamily: "var(--font-geist-mono)" }}>
                          {f.cwe}
                        </span>
                      )}
                      {f.priority_score != null && (
                        <span>
                          Priority {f.priority_score.toFixed(2)}
                        </span>
                      )}
                    </div>
                  </div>
                  {status && <StatusBadge status={status.status} />}
                  {status?.pr_url && (
                    <a
                      href={status.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-ghost"
                      style={{ color: "var(--brand)" }}
                    >
                      <GitPullRequest size={13} />
                      View PR
                    </a>
                  )}
                  <button
                    onClick={() => startFix(f.id)}
                    disabled={status?.status === "running"}
                    className="btn-primary"
                  >
                    <Wrench size={13} />
                    {status?.status === "completed" ? "Re-fix" : "Fix"}
                  </button>
                </div>

                {status?.message && (
                  <div
                    className="mt-3 text-xs rounded-lg p-2"
                    style={{
                      background: status.status === "failed" ? "var(--critical-soft)" : "var(--surface-2)",
                      color: status.status === "failed" ? "var(--critical)" : "var(--ink-2)",
                    }}
                  >
                    {status.message}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
