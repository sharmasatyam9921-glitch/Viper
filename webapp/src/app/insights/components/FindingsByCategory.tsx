'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getSeverityPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { SecurityFinding } from '../types'

interface FindingsByCategoryProps {
  data: SecurityFinding[] | undefined
  isLoading: boolean
}

const SEV_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

export function FindingsByCategory({ data, isLoading }: FindingsByCategoryProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getSeverityPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, { category: string; count: number; maxSeverity: string; weight: number }>()
    for (const f of data) {
      const cat = f.category || f.findingSource || 'other'
      const sev = f.severity?.toLowerCase() || 'unknown'
      const w = SEV_WEIGHT[sev] ?? 0
      const existing = map.get(cat)
      if (!existing) {
        map.set(cat, { category: cat, count: 1, maxSeverity: sev, weight: w })
      } else {
        existing.count++
        if (w > existing.weight) { existing.maxSeverity = sev; existing.weight = w }
      }
    }
    return [...map.values()]
      .sort((a, b) => b.count - a.count)
      .slice(0, 12)
  }, [data])

  return (
    <ChartCard title="Finding Categories" subtitle={`Top ${chartData.length} categories`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="category"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={85}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16} name="Findings">
            {chartData.map((entry) => (
              <Cell
                key={entry.category}
                fill={palette[entry.maxSeverity as keyof typeof palette] || palette.unknown}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
