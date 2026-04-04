'use client'

import { Activity, Shield, Github, Terminal } from 'lucide-react'
import { formatNumber } from '../utils/formatters'
import type { PipelineStatusData } from '../types'
import type { SessionsData } from '@/lib/websocket-types'
import styles from './KPICards.module.css'

interface KPI {
  label: string
  value: number
  accent?: string
}

interface KPICardsProps {
  items: KPI[]
  isLoading?: boolean
  pipeline?: PipelineStatusData | undefined
  sessions?: SessionsData | undefined
}

function PipelineCard({ label, icon, status, phase }: {
  label: string
  icon: React.ReactNode
  status: string | undefined
  phase?: string
}) {
  const s = status?.toLowerCase() || 'idle'
  let dotCls = styles.dotIdle
  if (s === 'running' || s === 'starting') dotCls = styles.dotRunning
  else if (s === 'completed') dotCls = styles.dotCompleted
  else if (s === 'error' || s === 'failed') dotCls = styles.dotError
  else if (s === 'paused') dotCls = styles.dotPaused

  return (
    <div className="statCard">
      <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {icon}{label}
      </div>
      <div className={styles.pipelineStatus}>
        <span className={`${styles.dot} ${dotCls}`} />
        <span className={styles.statusText}>{status || 'idle'}</span>
        {phase && <span className={styles.phase}>{phase}</span>}
      </div>
    </div>
  )
}

function SessionsCard({ sessions }: { sessions: SessionsData | undefined }) {
  const msf = sessions?.sessions || []
  const nonMsf = sessions?.non_msf_sessions || []
  const total = msf.length + nonMsf.length

  return (
    <div className="statCard">
      <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Terminal size={12} />Active Shells
      </div>
      <div className="statValue" style={total > 0 ? { color: 'var(--status-success)' } : undefined}>
        {total}
      </div>
    </div>
  )
}

export function KPICards({ items, isLoading, pipeline, sessions }: KPICardsProps) {
  if (isLoading) {
    return (
      <div className={styles.grid}>
        {Array.from({ length: 10 }).map((_, i) => (
          <div key={i} className="statCard">
            <div className={`statLabel ${styles.skeletonLabel}`} />
            <div className={`statValue ${styles.skeletonValue}`} />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className={styles.grid}>
      {items.map((kpi) => (
        <div key={kpi.label} className="statCard">
          <div className="statLabel">{kpi.label}</div>
          <div className="statValue" style={kpi.accent ? { color: kpi.accent } : undefined}>
            {formatNumber(kpi.value)}
          </div>
        </div>
      ))}
      <SessionsCard sessions={sessions} />
      <PipelineCard label="Recon Pipeline" icon={<Activity size={12} />} status={pipeline?.recon?.status} phase={pipeline?.recon?.currentPhase} />
      <PipelineCard label="GVM Scan" icon={<Shield size={12} />} status={pipeline?.gvm?.status} />
      <PipelineCard label="GitHub Hunt" icon={<Github size={12} />} status={pipeline?.githubHunt?.status} />
    </div>
  )
}
