'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface FindingTypesBarProps {
  data: { findingType: string; count: number }[] | undefined
  isLoading: boolean
}

function formatType(t: string): string {
  return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function FindingTypesBar({ data, isLoading }: FindingTypesBarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    return data.slice(0, 10).map(d => ({ ...d, label: formatType(d.findingType) }))
  }, [data])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0

  return (
    <ChartCard title="Finding Types" subtitle={`${total} findings`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={110}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16} name="Count">
            {chartData.map((_, i) => (
              <Cell key={i} fill={palette[i % palette.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
