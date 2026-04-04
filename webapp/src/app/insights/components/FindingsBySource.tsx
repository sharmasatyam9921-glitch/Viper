'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getSeverityPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { SecurityFinding } from '../types'

interface FindingsBySourceProps {
  data: SecurityFinding[] | undefined
  isLoading: boolean
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export function FindingsBySource({ data, isLoading }: FindingsBySourceProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getSeverityPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, Record<string, string | number>>()
    for (const f of data) {
      const source = f.findingSource || 'Unknown'
      const sev = f.severity?.toLowerCase() || 'unknown'
      if (!map.has(source)) map.set(source, { source, critical: 0, high: 0, medium: 0, low: 0, info: 0 })
      const row = map.get(source)!
      if (sev in row) (row as Record<string, number>)[sev]++
    }
    return [...map.values()].sort((a, b) => {
      const totalA = SEVERITIES.reduce((s, k) => s + ((a as Record<string, number>)[k] || 0), 0)
      const totalB = SEVERITIES.reduce((s, k) => s + ((b as Record<string, number>)[k] || 0), 0)
      return totalB - totalA
    })
  }, [data])

  const total = data?.length || 0

  return (
    <ChartCard title="Findings by Source" subtitle={`${total} findings across scanners`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="source"
            tick={{ fontSize: 11, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={75}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11, textTransform: 'capitalize' }}>{value}</span>} />
          {SEVERITIES.map(sev => (
            <Bar key={sev} dataKey={sev} stackId="a" fill={palette[sev]} name={sev} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
