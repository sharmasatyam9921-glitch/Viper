'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface PhaseProgressionBarProps {
  data: { phase: string; totalSteps: number; successSteps: number }[] | undefined
  isLoading: boolean
}

function formatPhase(p: string): string {
  return p.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function PhaseProgressionBar({ data, isLoading }: PhaseProgressionBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    return data.map(d => ({
      phase: formatPhase(d.phase),
      success: d.successSteps,
      failed: d.totalSteps - d.successSteps,
    }))
  }, [data])

  const totalSteps = data?.reduce((s, d) => s + d.totalSteps, 0) || 0

  return (
    <ChartCard title="Phase Progression" subtitle={`${totalSteps} total steps`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="phase"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            interval={0}
            angle={-20}
            textAnchor="end"
            height={50}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} width={35} />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11, textTransform: 'capitalize' }}>{value}</span>} />
          <Bar dataKey="success" stackId="a" fill="#22c55e" radius={[0, 0, 0, 0]} maxBarSize={32} name="Success" />
          <Bar dataKey="failed" stackId="a" fill="#e53935" radius={[4, 4, 0, 0]} maxBarSize={32} name="Failed" />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
