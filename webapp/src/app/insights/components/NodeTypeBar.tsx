'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getNodeTypePalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface NodeTypeBarProps {
  data: { label: string; count: number }[] | undefined
  isLoading: boolean
}

export function NodeTypeBar({ data, isLoading }: NodeTypeBarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getNodeTypePalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => data?.slice(0, 10) || [], [data])

  return (
    <ChartCard title="Nodes by Type" subtitle={`Top ${chartData.length} types`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={85}
            interval={0}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18}>
            {chartData.map((entry) => (
              <Cell key={entry.label} fill={palette[entry.label as keyof typeof palette] || chrome.axisColor} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
