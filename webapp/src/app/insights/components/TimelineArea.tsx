'use client'

import { useMemo } from 'react'
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { formatDate } from '../utils/formatters'
import { ChartCard } from './ChartCard'

interface TimelineAreaProps {
  data: { date: string; count: number; [key: string]: unknown }[] | undefined
  isLoading: boolean
  title?: string
  color?: string
  dataKey?: string
}

export function TimelineArea({ data, isLoading, title = 'Findings Over Time', color = '#e53935', dataKey = 'count' }: TimelineAreaProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  return (
    <ChartCard title={title} subtitle={`${data?.length || 0} days`} isLoading={isLoading} isEmpty={!data?.length}>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data || []} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <defs>
            <linearGradient id={`gradient-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.3} />
              <stop offset="95%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="date"
            tickFormatter={formatDate}
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} width={35} />
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} labelFormatter={formatDate} />
          <Area
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            fill={`url(#gradient-${dataKey})`}
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
