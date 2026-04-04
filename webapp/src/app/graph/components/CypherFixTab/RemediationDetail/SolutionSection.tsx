'use client'

import { memo } from 'react'
import { Lightbulb } from 'lucide-react'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface SolutionSectionProps {
  remediation: Remediation
}

export const SolutionSection = memo(function SolutionSection({ remediation }: SolutionSectionProps) {
  if (!remediation.solution) return null

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <Lightbulb size={14} />
        Suggested Solution
      </h4>
      <div className={styles.solutionText}>{remediation.solution}</div>

      <div className={styles.metaRow}>
        <span className={styles.metaLabel}>Complexity:</span>
        <span className={styles.metaValue}>{remediation.fixComplexity}</span>
        <span className={styles.metaLabel}>Est. files:</span>
        <span className={styles.metaValue}>{remediation.estimatedFiles}</span>
      </div>
    </div>
  )
})
