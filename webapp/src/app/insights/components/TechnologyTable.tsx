'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { ChartCard } from './ChartCard'
import styles from './DataTable.module.css'

interface TechnologyTableProps {
  data: { name: string; version: string | null; cveCount: number }[] | undefined
  isLoading: boolean
}

type SortKey = 'name' | 'version' | 'cveCount'

export function TechnologyTable({ data, isLoading }: TechnologyTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('cveCount')
  const [sortAsc, setSortAsc] = useState(false)

  const sorted = useMemo(() => {
    if (!data) return []
    return [...data].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'name') cmp = a.name.localeCompare(b.name)
      else if (sortKey === 'version') cmp = (a.version || '').localeCompare(b.version || '')
      else cmp = a.cveCount - b.cveCount
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
    <ChartCard title="Technologies" subtitle={`${data?.length || 0} detected`} isLoading={isLoading} isEmpty={!sorted.length}>
      <div className={styles.tableWrap}>
        <table className="table">
          <thead className="tableHeader">
            <tr>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('name')}>
                Technology <SortIcon col="name" />
              </th>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('version')}>
                Version <SortIcon col="version" />
              </th>
              <th className={`tableHeaderCell tableHeaderSortable`} onClick={() => toggleSort('cveCount')}>
                CVEs <SortIcon col="cveCount" />
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, i) => (
              <tr key={i} className="tableRow">
                <td className="tableCell">{row.name}</td>
                <td className="tableCell tableCellMono">{row.version || '-'}</td>
                <td className="tableCell tableCellMono">
                  {row.cveCount > 0 ? (
                    <span className={styles.cveBadge}>{row.cveCount}</span>
                  ) : (
                    <span style={{ color: 'var(--text-tertiary)' }}>0</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartCard>
  )
}
