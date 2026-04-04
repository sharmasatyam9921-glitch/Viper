'use client'

import { Shield, Scan, ArrowDown, Brain } from 'lucide-react'
import styles from './EmptyState.module.css'

interface EmptyStateProps {
  onStartTriage: () => void
}

export function EmptyState({ onStartTriage }: EmptyStateProps) {
  return (
    <div className={styles.wrapper}>
      <div className={styles.card}>
        <div className={styles.iconWrapper}>
          <Shield size={48} strokeWidth={1.5} />
        </div>
        <h2 className={styles.title}>No Remediations Yet</h2>
        <p className={styles.description}>
          Run a vulnerability triage analysis to scan your Neo4j graph for security
          findings, correlate them, and generate prioritized remediation items.
        </p>
        <div className={styles.steps}>
          <div className={styles.step}>
            <Scan size={16} />
            <span>Collect findings from graph</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <Brain size={16} />
            <span>AI-powered triage &amp; prioritization</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <Shield size={16} />
            <span>Actionable remediations</span>
          </div>
        </div>
        <button className={styles.startButton} onClick={onStartTriage}>
          <Scan size={16} />
          Start Vulnerability Triage
        </button>
      </div>
    </div>
  )
}
