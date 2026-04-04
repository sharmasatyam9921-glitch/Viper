'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface DnsRecordsPieProps {
  data: { type: string; count: number }[] | undefined
  isLoading: boolean
}

export function DnsRecordsPie({ data, isLoading }: DnsRecordsPieProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data || !data.length) return []
    const top = data.slice(0, 8)
    const rest = data.slice(8)
    if (rest.length > 0) {
      top.push({ type: 'Other', count: rest.reduce((s, d) => s + d.count, 0) })
    }
    return top
  }, [data])

  const total = chartData.reduce((s, d) => s + d.count, 0)

  return (
    <ChartCard title="DNS Records" subtitle={`${total} records`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="count"
            nameKey="type"
            cx="50%"
            cy="50%"
            outerRadius={70}
            paddingAngle={1}
            stroke="none"
          >
            {chartData.map((_, i) => (
              <Cell key={i} fill={palette[i % palette.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend
            formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
