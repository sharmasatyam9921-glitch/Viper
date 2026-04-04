'use client'

import { memo } from 'react'
import { Filter, X } from 'lucide-react'
import type { RemediationSeverity, RemediationStatus } from '@/lib/cypherfix-types'
import styles from './RemediationDashboard.module.css'

const SEVERITIES: RemediationSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES: RemediationStatus[] = ['pending', 'in_progress', 'no_fix', 'code_review', 'pr_created', 'resolved', 'dismissed']

const STATUS_LABELS: Record<RemediationStatus, string> = {
  pending: 'Pending',
  in_progress: 'In Progress',
  no_fix: 'No Fix',
  code_review: 'Code Review',
  pr_created: 'PR Created',
  resolved: 'Resolved',
  dismissed: 'Dismissed',
}

interface RemediationFiltersProps {
  severityFilter?: RemediationSeverity
  statusFilter?: RemediationStatus
  onSeverityChange: (severity: RemediationSeverity | undefined) => void
  onStatusChange: (status: RemediationStatus | undefined) => void
}

export const RemediationFilters = memo(function RemediationFilters({
  severityFilter,
  statusFilter,
  onSeverityChange,
  onStatusChange,
}: RemediationFiltersProps) {
  const hasFilters = !!severityFilter || !!statusFilter

  return (
    <div className={styles.filters}>
      <Filter size={12} className={styles.filterIcon} />

      <select
        className={styles.filterSelect}
        value={severityFilter || ''}
        onChange={e => onSeverityChange((e.target.value || undefined) as RemediationSeverity | undefined)}
      >
        <option value="">All Severities</option>
        {SEVERITIES.map(s => (
          <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
        ))}
      </select>

      <select
        className={styles.filterSelect}
        value={statusFilter || ''}
        onChange={e => onStatusChange((e.target.value || undefined) as RemediationStatus | undefined)}
      >
        <option value="">All Statuses</option>
        {STATUSES.map(s => (
          <option key={s} value={s}>{STATUS_LABELS[s]}</option>
        ))}
      </select>

      {hasFilters && (
        <button
          className={styles.clearFilters}
          onClick={() => {
            onSeverityChange(undefined)
            onStatusChange(undefined)
          }}
        >
          <X size={12} />
          Clear
        </button>
      )}
    </div>
  )
})
