'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { CveChain } from '../types'

interface AttackPatternsBarProps {
  data: CveChain[] | undefined
  isLoading: boolean
}

export function AttackPatternsBar({ data, isLoading }: AttackPatternsBarProps) {
  const { theme } = useTheme()
  const colors = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    // Count unique CAPEC patterns and the CVEs they relate to
    const map = new Map<string, { pattern: string; cveCount: number; uniqueCves: Set<string> }>()
    for (const row of data) {
      if (!row.capecId || !row.capecName) continue
      const key = row.capecId
      const existing = map.get(key)
      if (!existing) {
        map.set(key, { pattern: `${row.capecId}: ${row.capecName}`, cveCount: 0, uniqueCves: new Set([row.cveId]) })
      } else {
        existing.uniqueCves.add(row.cveId)
      }
    }
    return [...map.values()]
      .map(v => ({
        pattern: v.pattern.length > 35 ? v.pattern.slice(0, 32) + '...' : v.pattern,
        fullPattern: v.pattern,
        cveCount: v.uniqueCves.size,
      }))
      .sort((a, b) => b.cveCount - a.cveCount)
      .slice(0, 10)
  }, [data])

  // Also extract CWE summary
  const cweSummary = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, { cwe: string; count: number }>()
    for (const row of data) {
      if (!row.cweId) continue
      const existing = map.get(row.cweId)
      if (!existing) {
        map.set(row.cweId, { cwe: `${row.cweId}: ${row.cweName || ''}`, count: 1 })
      } else {
        existing.count++
      }
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 8)
  }, [data])

  const isEmpty = !chartData.length && !cweSummary.length

  return (
    <ChartCard
      title="Attack Patterns (CAPEC)"
      subtitle={`${chartData.length} patterns linked to CVEs`}
      isLoading={isLoading}
      isEmpty={isEmpty}
    >
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="pattern"
            tick={{ fontSize: 9, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={135}
          />
          <Tooltip
            cursor={cursorStyle}
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number) => [value, 'Related CVEs']}
          />
          <Bar dataKey="cveCount" radius={[0, 4, 4, 0]} maxBarSize={14} name="Related CVEs">
            {chartData.map((entry, i) => (
              <Cell key={entry.pattern} fill={colors[i % colors.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
