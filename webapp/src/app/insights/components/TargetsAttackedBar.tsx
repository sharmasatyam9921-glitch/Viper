'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface TargetsAttackedBarProps {
  data: { targetHost: string; targetType: string | null; attackCount: number; successCount: number }[] | undefined
  isLoading: boolean
}

export function TargetsAttackedBar({ data, isLoading }: TargetsAttackedBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    return data.slice(0, 10).map(d => ({
      ...d,
      host: d.targetHost.length > 14 ? d.targetHost.slice(0, 12) + '…' : d.targetHost,
    }))
  }, [data])

  return (
    <ChartCard title="Targets Attacked" subtitle={`${data?.length || 0} targets`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="host"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={70}
          />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
          <Bar dataKey="attackCount" fill="#3b82f6" radius={[0, 4, 4, 0]} maxBarSize={12} name="Attacks" />
          <Bar dataKey="successCount" fill="#22c55e" radius={[0, 4, 4, 0]} maxBarSize={12} name="Successes" />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
