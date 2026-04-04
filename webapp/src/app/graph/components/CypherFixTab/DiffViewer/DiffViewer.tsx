'use client'

import { useCallback, useMemo } from 'react'
import { ArrowLeft, Loader2 } from 'lucide-react'
import { ActivityLog } from './ActivityLog'
import { useCypherFixCodeFixWS } from '@/hooks/useCypherFixCodeFixWS'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './DiffViewer.module.css'

interface DiffViewerProps {
  remediation: Remediation
  projectId: string
  userId: string
  onBack: () => void
  onRefresh: () => void
}

export function DiffViewer({
  remediation,
  projectId,
  userId,
  onBack,
  onRefresh,
}: DiffViewerProps) {
  const codefix = useCypherFixCodeFixWS({
    userId,
    projectId,
    onComplete: () => {
      onRefresh()
    },
  })

  const handleStart = useCallback(() => {
    codefix.startFix(remediation.id)
  }, [codefix, remediation.id])

  const handleAccept = useCallback((blockId: string) => {
    codefix.sendBlockDecision(blockId, 'accept')
  }, [codefix])

  const handleReject = useCallback((blockId: string, reason?: string) => {
    codefix.sendBlockDecision(blockId, 'reject', reason)
  }, [codefix])

  // Stats
  const blockStats = useMemo(() => {
    const accepted = codefix.diffBlocks.filter(b => b.status === 'accepted').length
    const rejected = codefix.diffBlocks.filter(b => b.status === 'rejected').length
    const pending = codefix.diffBlocks.filter(b => b.status === 'pending').length
    return { total: codefix.diffBlocks.length, accepted, rejected, pending }
  }, [codefix.diffBlocks])

  const isRunning = codefix.status === 'running' || codefix.status === 'awaiting_approval'
  const isProcessing = codefix.status === 'running'
  const isStopping = codefix.status === 'stopping'
  const isIdle = codefix.status === 'disconnected' || codefix.status === 'connected'

  return (
    <div className={styles.viewer}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <button className={styles.backBtn} onClick={onBack}>
            <ArrowLeft size={14} />
            Back
          </button>
          <span className={styles.remTitle}>{remediation.title}</span>
        </div>
        <div className={styles.headerRight}>
          {blockStats.total > 0 && (
            <span className={styles.statsLabel}>
              {blockStats.accepted} accepted, {blockStats.rejected} rejected, {blockStats.pending} pending
            </span>
          )}
          {isStopping && (
            <span className={styles.stoppingLabel}>
              <Loader2 size={14} className={styles.spinner} />
              Stopping...
            </span>
          )}
          {isRunning && (
            <button className={styles.stopBtn} onClick={codefix.stopFix}>
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Processing indicator */}
      {isProcessing && (
        <div className={styles.processingBar}>
          <Loader2 size={14} className={styles.spinner} />
          Processing...
        </div>
      )}

      {/* Content */}
      <div className={styles.content}>
        {/* Idle state — show start button (first time or after stop) */}
        {isIdle && codefix.activityLog.length === 0 && (
          <div className={styles.idleState}>
            <p>Ready to start the CodeFix agent for this remediation.</p>
            <button className={styles.startBtn} onClick={handleStart}>
              Start CodeFix
            </button>
          </div>
        )}

        {/* Activity log — chronological history of all events */}
        {codefix.activityLog.length > 0 && (
          <ActivityLog
            entries={codefix.activityLog}
            diffBlocks={codefix.diffBlocks}
            onAcceptBlock={handleAccept}
            onRejectBlock={handleReject}
          />
        )}

        {/* Restart / Go to Remediations — shown when idle after a previous run */}
        {isIdle && codefix.activityLog.length > 0 && (
          <div className={styles.idleState}>
            <button className={styles.startBtn} onClick={handleStart}>
              Restart CodeFix
            </button>
            <button className={styles.secondaryBtn} onClick={onBack}>
              Go to Remediations
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
