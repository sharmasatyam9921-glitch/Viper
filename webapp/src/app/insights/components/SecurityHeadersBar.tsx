'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface SecurityHeadersBarProps {
  data: { name: string; isSecurity: boolean; count: number }[] | undefined
  isLoading: boolean
}

function formatName(name: string): string {
  return name.replace(/_/g, '-')
}

export function SecurityHeadersBar({ data, isLoading }: SecurityHeadersBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    return data.slice(0, 12).map(d => ({
      ...d,
      label: formatName(d.name),
    }))
  }, [data])

  const secCount = useMemo(() => data?.filter(d => d.isSecurity).length || 0, [data])

  return (
    <ChartCard
      title="Security Headers"
      subtitle={`${secCount} security / ${(data?.length || 0) - secCount} other across ${data?.length || 0} headers`}
      isLoading={isLoading}
      isEmpty={!chartData.length}
    >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={90}
          />
          <Tooltip
            cursor={cursorStyle}
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _name: string, props: { payload?: { isSecurity: boolean } }) =>
              [value, props.payload?.isSecurity ? 'Security' : 'Standard']
            }
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16}>
            {chartData.map((entry, i) => (
              <Cell key={i} fill={entry.isSecurity ? '#22c55e' : '#3b82f6'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
