'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface HeaderInsightsPieProps {
  data: { category: string; count: number }[] | undefined
  isLoading: boolean
}

const CATEGORY_COLORS: Record<string, string> = {
  Security: '#22c55e',
  'Tech-Revealing': '#f97316',
  Informational: '#71717a',
}

export function HeaderInsightsPie({ data, isLoading }: HeaderInsightsPieProps) {
  const { theme } = useTheme()
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0

  return (
    <ChartCard title="Header Categories" subtitle={`${total} unique headers`} isLoading={isLoading} isEmpty={!data?.length}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data || []}
            dataKey="count"
            nameKey="category"
            cx="50%"
            cy="50%"
            outerRadius={70}
            paddingAngle={2}
            stroke="none"
          >
            {(data || []).map((entry) => (
              <Cell key={entry.category} fill={CATEGORY_COLORS[entry.category] || '#71717a'} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
