'use client'

import { memo } from 'react'
import { Clock, Play, Eye, GitPullRequest, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { STATUS_LABELS, type RemediationStatus } from '@/lib/cypherfix-types'

const STATUS_CONFIG: Record<RemediationStatus, { icon: typeof Clock; color: string }> = {
  pending: { icon: Clock, color: 'var(--text-tertiary)' },
  in_progress: { icon: Play, color: 'var(--accent-primary)' },
  no_fix: { icon: AlertTriangle, color: 'var(--severity-medium, #ca8a04)' },
  code_review: { icon: Eye, color: 'var(--severity-medium, #ca8a04)' },
  pr_created: { icon: GitPullRequest, color: 'var(--severity-high, #ea580c)' },
  resolved: { icon: CheckCircle, color: 'var(--success, #16a34a)' },
  dismissed: { icon: XCircle, color: 'var(--text-tertiary)' },
}

interface StatusBadgeProps {
  status: RemediationStatus
}

export const StatusBadge = memo(function StatusBadge({ status }: StatusBadgeProps) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.pending
  const Icon = config.icon

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: 'var(--radius-md)',
        fontSize: '11px',
        fontWeight: 500,
        color: config.color,
        background: `color-mix(in srgb, ${config.color} 10%, transparent)`,
      }}
    >
      <Icon size={12} />
      {STATUS_LABELS[status]}
    </span>
  )
})
