'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { CveChain } from '../types'

interface CweBreakdownBarProps {
  data: CveChain[] | undefined
  isLoading: boolean
}

export function CweBreakdownBar({ data, isLoading }: CweBreakdownBarProps) {
  const { theme } = useTheme()
  const colors = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, { cweId: string; cweName: string; cves: Set<string> }>()
    for (const row of data) {
      if (!row.cweId) continue
      const existing = map.get(row.cweId)
      if (!existing) {
        map.set(row.cweId, { cweId: row.cweId, cweName: row.cweName || row.cweId, cves: new Set([row.cveId]) })
      } else {
        existing.cves.add(row.cveId)
      }
    }
    return [...map.values()]
      .map(v => ({ cwe: `${v.cweId}`, name: v.cweName, count: v.cves.size }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)
  }, [data])

  const totalCwes = chartData.length

  return (
    <ChartCard title="Top CWE Weaknesses" subtitle={`${totalCwes} weakness classes`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="cwe"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={75}
          />
          <Tooltip
            cursor={cursorStyle}
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _: string, props: { payload?: { name: string } }) => [
              value,
              props.payload?.name ?? '',
            ]}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16} name="CVEs">
            {chartData.map((_, i) => (
              <Cell key={i} fill={colors[i % colors.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
