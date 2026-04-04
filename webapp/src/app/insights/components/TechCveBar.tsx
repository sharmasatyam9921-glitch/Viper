'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getSeverityPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { CveChain } from '../types'

interface TechCveBarProps {
  data: CveChain[] | undefined
  isLoading: boolean
}

const SEV_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

export function TechCveBar({ data, isLoading }: TechCveBarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getSeverityPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, { tech: string; cveCount: number; maxSeverity: string; weight: number; uniqueCves: Set<string> }>()
    for (const row of data) {
      const key = row.techVersion ? `${row.tech} ${row.techVersion}` : row.tech
      const sev = (row.cveSeverity || 'unknown').toLowerCase()
      const w = SEV_WEIGHT[sev] ?? 0
      const existing = map.get(key)
      if (!existing) {
        map.set(key, { tech: key, cveCount: 0, maxSeverity: sev, weight: w, uniqueCves: new Set([row.cveId]) })
      } else {
        existing.uniqueCves.add(row.cveId)
        if (w > existing.weight) { existing.maxSeverity = sev; existing.weight = w }
      }
    }
    return [...map.values()]
      .map(v => ({ tech: v.tech, cveCount: v.uniqueCves.size, maxSeverity: v.maxSeverity }))
      .sort((a, b) => b.cveCount - a.cveCount)
      .slice(0, 10)
  }, [data])

  const totalCves = useMemo(() => {
    if (!data) return 0
    return new Set(data.map(d => d.cveId)).size
  }, [data])

  return (
    <ChartCard title="CVEs by Technology" subtitle={`${totalCves} CVEs across technologies`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="tech"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={70}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="cveCount" radius={[0, 4, 4, 0]} maxBarSize={16} name="CVEs">
            {chartData.map((entry) => (
              <Cell
                key={entry.tech}
                fill={palette[entry.maxSeverity as keyof typeof palette] || palette.unknown}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
