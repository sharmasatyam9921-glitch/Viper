'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface ChainSuccessRatePieProps {
  data: { status: string; count: number }[] | undefined
  isLoading: boolean
}

const STATUS_COLORS: Record<string, string> = {
  completed: '#22c55e',
  active: '#3b82f6',
  aborted: '#e53935',
  unknown: '#71717a',
}

export function ChainSuccessRatePie({ data, isLoading }: ChainSuccessRatePieProps) {
  const { theme } = useTheme()
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0

  return (
    <ChartCard title="Chain Status" subtitle={`${total} chains`} isLoading={isLoading} isEmpty={total === 0}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="status"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
            stroke="none"
          >
            {data?.map((entry) => (
              <Cell key={entry.status} fill={STATUS_COLORS[entry.status] || STATUS_COLORS.unknown} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11, textTransform: 'capitalize' }}>{value}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
