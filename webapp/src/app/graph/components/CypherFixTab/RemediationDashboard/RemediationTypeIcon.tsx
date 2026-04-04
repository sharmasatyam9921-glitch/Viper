'use client'

import { memo } from 'react'
import { Code, Package, Settings, KeyRound, Server } from 'lucide-react'
import { REMEDIATION_TYPE_LABELS, type RemediationType } from '@/lib/cypherfix-types'

const TYPE_ICONS: Record<RemediationType, typeof Code> = {
  code_fix: Code,
  dependency_update: Package,
  config_change: Settings,
  secret_rotation: KeyRound,
  infrastructure: Server,
}

interface RemediationTypeIconProps {
  type: RemediationType
  size?: number
  showLabel?: boolean
}

export const RemediationTypeIcon = memo(function RemediationTypeIcon({
  type,
  size = 14,
  showLabel = true,
}: RemediationTypeIconProps) {
  const Icon = TYPE_ICONS[type] || Code
  const label = REMEDIATION_TYPE_LABELS[type] || type

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: '11px',
        color: 'var(--text-secondary)',
      }}
    >
      <Icon size={size} />
      {showLabel && <span>{label}</span>}
    </span>
  )
})
