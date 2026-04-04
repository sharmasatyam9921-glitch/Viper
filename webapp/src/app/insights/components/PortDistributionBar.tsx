'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface PortDistributionBarProps {
  data: { port: number; protocol: string; count: number }[] | undefined
  isLoading: boolean
}

export function PortDistributionBar({ data, isLoading }: PortDistributionBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data) return []
    return data.slice(0, 15).map(d => ({ ...d, label: `${d.port}/${d.protocol}` }))
  }, [data])

  return (
    <ChartCard title="Open Ports" subtitle={`${data?.length || 0} unique`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="label"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            interval={0}
            angle={-45}
            textAnchor="end"
            height={50}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} width={35} />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} maxBarSize={24} name="Instances" />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
