'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getSeverityPalette, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface SeverityDonutProps {
  data: { severity: string; count: number }[] | undefined
  isLoading: boolean
  title?: string
}

export function SeverityDonut({ data, isLoading, title = 'Vulnerability Severity' }: SeverityDonutProps) {
  const { theme } = useTheme()

  const palette = useMemo(() => getSeverityPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data) return []
    const order = ['critical', 'high', 'medium', 'low', 'info']
    const idx = (s: string) => { const i = order.indexOf(s?.toLowerCase()); return i === -1 ? 99 : i }
    return [...data].sort((a, b) => idx(a.severity) - idx(b.severity))
  }, [data])

  const total = chartData.reduce((s, d) => s + d.count, 0)

  return (
    <ChartCard title={title} subtitle={`${total} total`} isLoading={isLoading} isEmpty={total === 0}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
            stroke="none"
          >
            {chartData.map((entry) => (
              <Cell
                key={entry.severity}
                fill={palette[entry.severity?.toLowerCase() as keyof typeof palette] || palette.unknown}
              />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend
            formatter={(value: string) => <span style={{ fontSize: 11, textTransform: 'capitalize' }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
