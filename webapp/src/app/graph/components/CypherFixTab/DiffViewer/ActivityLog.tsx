'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Brain,
  Wrench,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ChevronRight,
  GitPullRequest,
  ExternalLink,
  ClipboardList,
  ChevronDown,
} from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { DiffBlock as DiffBlockComponent } from './DiffBlock'
import type { ActivityEntry, DiffBlockPayload, FixPlanPayload, PRCreatedPayload } from '@/lib/cypherfix-types'
import styles from './ActivityLog.module.css'

interface ActivityLogProps {
  entries: ActivityEntry[]
  diffBlocks: DiffBlockPayload[]
  onAcceptBlock: (blockId: string) => void
  onRejectBlock: (blockId: string, reason?: string) => void
}

export function ActivityLog({ entries, diffBlocks, onAcceptBlock, onRejectBlock }: ActivityLogProps) {
  const logRef = useRef<HTMLDivElement>(null)
  const userScrolledRef = useRef(false)

  // Auto-scroll to bottom unless user scrolled up
  useEffect(() => {
    if (!logRef.current || userScrolledRef.current) return
    logRef.current.scrollTop = logRef.current.scrollHeight
  }, [entries])

  const handleScroll = useCallback(() => {
    if (!logRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logRef.current
    // Consider "at bottom" if within 60px
    userScrolledRef.current = scrollHeight - scrollTop - clientHeight > 60
  }, [])

  return (
    <div className={styles.log} ref={logRef} onScroll={handleScroll}>
      {entries.map((entry) => {
        switch (entry.type) {
          case 'phase':
            return <PhaseEntry key={entry.id} phase={entry.phase} description={entry.description} />
          case 'thinking':
            return <ThinkingEntry key={entry.id} text={entry.text} />
          case 'tool':
            return (
              <ToolEntry
                key={entry.id}
                name={entry.name}
                args={entry.args}
                status={entry.status}
                success={entry.success}
                output={entry.output}
              />
            )
          case 'diff_block':
            return (
              <DiffBlockEntry
                key={entry.id}
                block={entry.block}
                diffBlocks={diffBlocks}
                onAccept={onAcceptBlock}
                onReject={onRejectBlock}
              />
            )
          case 'fix_plan':
            return <PlanEntry key={entry.id} plan={entry.plan} />
          case 'pr_created':
            return <PREntry key={entry.id} pr={entry.pr} />
          case 'error':
            return <ErrorEntry key={entry.id} message={entry.message} />
          case 'complete':
            return <CompleteEntry key={entry.id} status={entry.completionStatus} />
          default:
            return null
        }
      })}
    </div>
  )
}

/* ── Phase separator ─────────────────────────────────── */

function PhaseEntry({ phase, description }: { phase: string; description: string }) {
  const label = description || phase.replace(/_/g, ' ')
  return (
    <div className={styles.phaseEntry}>
      <div className={styles.phaseLine} />
      <span className={styles.phaseLabel}>{label}</span>
      <div className={styles.phaseLine} />
    </div>
  )
}

/* ── Thinking block ─────────────────────────────────── */

function ThinkingEntry({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false)
  const lineCount = text.split('\n').length
  const isLong = lineCount > 3 || text.length > 300

  return (
    <div className={styles.thinkingEntry}>
      <div className={styles.thinkingHeader}>
        <Brain size={11} />
        Reasoning
      </div>
      <div className={`${styles.thinkingText} ${expanded ? styles.thinkingTextExpanded : ''}`}>
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
      </div>
      {isLong && (
        <button className={styles.thinkingToggle} onClick={() => setExpanded(!expanded)}>
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
    </div>
  )
}

/* ── Tool call card ─────────────────────────────────── */

function ToolEntry({
  name,
  args,
  status,
  success,
  output,
}: {
  name: string
  args: Record<string, unknown>
  status: 'running' | 'done' | 'error'
  success?: boolean
  output?: string
}) {
  const [expanded, setExpanded] = useState(false)

  const displayName = name.replace(/^github_/, '')
  const argsSummary = summarizeToolArgs(name, args)

  return (
    <div className={styles.toolEntry}>
      <div className={styles.toolHeader} onClick={() => setExpanded(!expanded)}>
        <ChevronRight
          size={12}
          className={styles.toolIcon}
          style={{ transform: expanded ? 'rotate(90deg)' : undefined, transition: 'transform 0.15s' }}
        />
        <Wrench size={12} className={styles.toolIcon} />
        <span className={styles.toolName}>{displayName}</span>
        {argsSummary && <span className={styles.toolArgsSummary}>{argsSummary}</span>}
        {status === 'running' && <Loader2 size={14} className={styles.toolSpinner} />}
        {status === 'done' && success && <CheckCircle2 size={14} className={styles.toolStatusDone} />}
        {status === 'error' && <XCircle size={14} className={styles.toolStatusError} />}
        {status === 'done' && !success && <XCircle size={14} className={styles.toolStatusError} />}
      </div>
      {expanded && (
        <div className={styles.toolBody}>
          <div className={styles.toolArgs}>{JSON.stringify(args, null, 2)}</div>
          {output && (
            <>
              <div className={styles.toolOutputLabel}>Output</div>
              <div className={styles.toolOutput}>{output}</div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function summarizeToolArgs(name: string, args: Record<string, unknown>): string {
  if (name === 'github_read' || name === 'github_edit' || name === 'github_write') {
    return String(args.file_path || '')
  }
  if (name === 'github_grep') {
    return `"${args.pattern || ''}" ${args.include ? `in ${args.include}` : ''}`
  }
  if (name === 'github_glob') {
    return String(args.pattern || '')
  }
  if (name === 'github_bash') {
    const cmd = String(args.command || '')
    return cmd.length > 80 ? cmd.slice(0, 80) + '...' : cmd
  }
  if (name === 'github_repo_map') {
    return ''
  }
  // Generic: show first string arg
  const firstVal = Object.values(args).find(v => typeof v === 'string')
  if (firstVal) {
    const s = String(firstVal)
    return s.length > 60 ? s.slice(0, 60) + '...' : s
  }
  return ''
}

/* ── Diff block (wraps existing DiffBlock component) ── */

function DiffBlockEntry({
  block,
  diffBlocks,
  onAccept,
  onReject,
}: {
  block: DiffBlockPayload
  diffBlocks: DiffBlockPayload[]
  onAccept: (blockId: string) => void
  onReject: (blockId: string, reason?: string) => void
}) {
  // Use the live block status from diffBlocks state (may have been updated by BLOCK_STATUS)
  const liveBlock = diffBlocks.find(b => b.block_id === block.block_id) || block
  const index = diffBlocks.findIndex(b => b.block_id === block.block_id)

  return (
    <div className={styles.diffBlockEntry}>
      <DiffBlockComponent
        block={liveBlock}
        index={index >= 0 ? index : 0}
        total={diffBlocks.length}
        onAccept={onAccept}
        onReject={onReject}
      />
    </div>
  )
}

/* ── Fix plan card ─────────────────────────────────── */

function PlanEntry({ plan }: { plan: FixPlanPayload }) {
  const [expanded, setExpanded] = useState(true)

  return (
    <div className={styles.planEntry}>
      <div className={styles.planHeader} onClick={() => setExpanded(!expanded)} style={{ cursor: 'pointer' }}>
        <ClipboardList size={14} />
        Fix Plan
        <span style={{ marginLeft: 'auto' }}>
          <ChevronDown size={12} style={{ transform: expanded ? undefined : 'rotate(-90deg)', transition: 'transform 0.15s' }} />
        </span>
      </div>
      {expanded && (
        <>
          {plan.approach && <div className={styles.planApproach}>{plan.approach}</div>}
          {plan.files && plan.files.length > 0 && (
            <div className={styles.planFiles}>
              {plan.files.map((f, i) => (
                <div key={i} className={styles.planFile}>
                  <span className={styles.planFileAction}>{f.action}</span>
                  <span>{f.path}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

/* ── PR created card ─────────────────────────────────── */

function PREntry({ pr }: { pr: PRCreatedPayload }) {
  return (
    <div className={styles.prEntry}>
      <GitPullRequest size={20} />
      <div className={styles.prInfo}>
        <span className={styles.prTitle}>{pr.title}</span>
        <span className={styles.prMeta}>
          {pr.files_changed} files changed, +{pr.additions} -{pr.deletions}
        </span>
      </div>
      <a
        href={pr.pr_url}
        target="_blank"
        rel="noopener noreferrer"
        className={styles.prLink}
      >
        View PR
        <ExternalLink size={12} />
      </a>
    </div>
  )
}

/* ── Error entry ─────────────────────────────────── */

function ErrorEntry({ message }: { message: string }) {
  return (
    <div className={styles.errorEntry}>
      <AlertCircle size={14} />
      {message}
    </div>
  )
}

/* ── Complete entry ─────────────────────────────────── */

function CompleteEntry({ status }: { status: string }) {
  return (
    <div className={styles.completeEntry}>
      <CheckCircle2 size={14} />
      CodeFix {status === 'completed' ? 'completed successfully' : status}
    </div>
  )
}
