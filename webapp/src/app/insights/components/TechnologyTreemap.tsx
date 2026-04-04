'use client'

import { useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './TechnologyTreemap.module.css'

interface TechnologyTreemapProps {
  data: { name: string; version: string | null; cveCount: number }[] | undefined
  isLoading: boolean
}

export function TechnologyTreemap({ data, isLoading }: TechnologyTreemapProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])

  const items = useMemo(() => {
    if (!data || !data.length) return []
    return data.slice(0, 20)
  }, [data])

  const maxCve = Math.max(...items.map(i => i.cveCount), 1)

  return (
    <ChartCard title="Technology Stack" subtitle={`${data?.length || 0} detected`} isLoading={isLoading} isEmpty={!items.length}>
      <div className={styles.grid}>
        {items.map((tech, i) => (
          <div
            key={tech.name}
            className={styles.cell}
            style={{
              backgroundColor: palette[i % palette.length],
              opacity: 0.3 + (tech.cveCount / maxCve) * 0.7,
            }}
            title={`${tech.name}${tech.version ? ` v${tech.version}` : ''} — ${tech.cveCount} CVEs`}
          >
            <span className={styles.name}>{tech.name}</span>
            {tech.cveCount > 0 && <span className={styles.badge}>{tech.cveCount}</span>}
          </div>
        ))}
      </div>
    </ChartCard>
  )
}
