'use client'

import { useMemo } from 'react'
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { formatDate } from '../utils/formatters'
import { ChartCard } from './ChartCard'

interface AgentActivityLineProps {
  data: { date: string; count: number; iterations: number }[] | undefined
  isLoading: boolean
}

export function AgentActivityLine({ data, isLoading }: AgentActivityLineProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  return (
    <ChartCard title="Agent Activity" subtitle="Sessions & iterations over time" isLoading={isLoading} isEmpty={!data?.length}>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data || []} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="date"
            tickFormatter={formatDate}
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} width={35} />
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} labelFormatter={formatDate} />
          <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} name="Sessions" />
          <Line type="monotone" dataKey="iterations" stroke="#a855f7" strokeWidth={2} dot={false} name="Iterations" />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
