'use client'

import { Activity, Shield, Github } from 'lucide-react'
import type { PipelineStatusData } from '../types'
import styles from './PipelineStatus.module.css'

interface PipelineStatusProps {
  data: PipelineStatusData | undefined
  isLoading: boolean
}

function StatusDot({ status }: { status: string | undefined }) {
  const s = status?.toLowerCase() || 'idle'
  let cls = styles.dotIdle
  if (s === 'running' || s === 'starting') cls = styles.dotRunning
  else if (s === 'completed') cls = styles.dotCompleted
  else if (s === 'error' || s === 'failed') cls = styles.dotError
  else if (s === 'paused') cls = styles.dotPaused
  return <span className={`${styles.dot} ${cls}`} />
}

function PipelineCard({ label, icon, status, phase }: {
  label: string
  icon: React.ReactNode
  status: string | undefined
  phase?: string
}) {
  return (
    <div className={styles.card}>
      <div className={styles.cardIcon}>{icon}</div>
      <div className={styles.cardInfo}>
        <div className={styles.cardLabel}>{label}</div>
        <div className={styles.cardStatus}>
          <StatusDot status={status} />
          <span>{status || 'idle'}</span>
          {phase && <span className={styles.phase}>{phase}</span>}
        </div>
      </div>
    </div>
  )
}

export function PipelineStatus({ data, isLoading }: PipelineStatusProps) {
  if (isLoading) {
    return (
      <div className={styles.grid}>
        {[0, 1, 2].map(i => (
          <div key={i} className={`${styles.card} ${styles.skeleton}`} />
        ))}
      </div>
    )
  }

  return (
    <div className={styles.grid}>
      <PipelineCard
        label="Recon Pipeline"
        icon={<Activity size={16} />}
        status={data?.recon?.status}
        phase={data?.recon?.currentPhase}
      />
      <PipelineCard
        label="GVM Scan"
        icon={<Shield size={16} />}
        status={data?.gvm?.status}
      />
      <PipelineCard
        label="GitHub Hunt"
        icon={<Github size={16} />}
        status={data?.githubHunt?.status}
      />
    </div>
  )
}
