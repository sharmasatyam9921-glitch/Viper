'use client'

import { memo } from 'react'
import { SEVERITY_COLORS, type RemediationSeverity } from '@/lib/cypherfix-types'

interface SeverityBadgeProps {
  severity: RemediationSeverity
}

export const SeverityBadge = memo(function SeverityBadge({ severity }: SeverityBadgeProps) {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '11px',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.02em',
        color,
        background: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      }}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          background: color,
        }}
      />
      {severity}
    </span>
  )
})
