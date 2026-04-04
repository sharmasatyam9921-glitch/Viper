'use client'

import { useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { severityColor } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './TopFindingsTable.module.css'
import type { AttackChainsData } from '../types'

interface TopFindingsTableProps {
  data: AttackChainsData['topFindings'] | undefined
  isLoading: boolean
}

function formatType(t: string): string {
  return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function TopFindingsTable({ data, isLoading }: TopFindingsTableProps) {
  return (
    <ChartCard title="Chain Findings" subtitle={`Top ${data?.length || 0} by severity`} isLoading={isLoading} isEmpty={!data?.length}>
      <div className={styles.wrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Type</th>
              <th>Target</th>
              <th>Phase</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((f, i) => (
              <tr key={i}>
                <td>
                  <span className={styles.sevBadge} style={{ background: severityColor(f.severity) }}>
                    {f.severity}
                  </span>
                </td>
                <td className={styles.titleCell} title={f.title}>{f.title}</td>
                <td className={styles.typeCell}>{formatType(f.findingType)}</td>
                <td className={styles.mono}>{f.targetHost || '—'}</td>
                <td className={styles.phaseCell}>{f.phase ? formatType(f.phase) : '—'}</td>
                <td className={styles.evidenceCell} title={f.evidence || undefined}>
                  {f.evidence ? (f.evidence.slice(0, 80) + (f.evidence.length > 80 ? '...' : '')) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartCard>
  )
}
