'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface EndpointCategoriesBarProps {
  data: { category: string; count: number }[] | undefined
  isLoading: boolean
}

export function EndpointCategoriesBar({ data, isLoading }: EndpointCategoriesBarProps) {
  const { theme } = useTheme()
  const colors = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0

  return (
    <ChartCard title="Endpoint Categories" subtitle={`${total} endpoints`} isLoading={isLoading} isEmpty={!data?.length}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data || []} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="category"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={32} name="Endpoints">
            {(data || []).map((_, i) => (
              <Cell key={i} fill={colors[i % colors.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
