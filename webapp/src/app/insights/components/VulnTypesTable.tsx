'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { severityColor } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './DataTable.module.css'

interface VulnTypesTableProps {
  data: { name: string; severity: string; source: string; count: number }[] | undefined
  isLoading: boolean
}

type SortKey = 'name' | 'severity' | 'count'

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }

export function VulnTypesTable({ data, isLoading }: VulnTypesTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('count')
  const [sortAsc, setSortAsc] = useState(false)

  const sorted = useMemo(() => {
    if (!data) return []
    return [...data].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'name') cmp = a.name.localeCompare(b.name)
      else if (sortKey === 'severity') cmp = (SEV_ORDER[a.severity?.toLowerCase()] ?? 5) - (SEV_ORDER[b.severity?.toLowerCase()] ?? 5)
      else cmp = a.count - b.count
      return sortAsc ? cmp : -cmp
    })
  }, [data, sortKey, sortAsc])

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(false) }
  }

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) return null
    return sortAsc ? <ChevronUp size={12} /> : <ChevronDown size={12} />
  }

  return (
    <ChartCard title="Vulnerability Types" subtitle={`${data?.length || 0} types`} isLoading={isLoading} isEmpty={!sorted.length}>
      <div className={styles.tableWrap}>
        <table className="table">
          <thead className="tableHeader">
            <tr>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('name')}>
                Name <SortIcon col="name" />
              </th>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('severity')}>
                Severity <SortIcon col="severity" />
              </th>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('count')}>
                Count <SortIcon col="count" />
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, i) => (
              <tr key={i} className="tableRow">
                <td className="tableCell tableCellTruncate">{row.name}</td>
                <td className="tableCell">
                  <span className={styles.sevBadge} style={{ color: severityColor(row.severity) }}>
                    {row.severity}
                  </span>
                </td>
                <td className="tableCell tableCellMono">{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartCard>
  )
}
