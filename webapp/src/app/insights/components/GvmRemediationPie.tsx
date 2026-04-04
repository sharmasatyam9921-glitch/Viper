'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface GvmRemediationPieProps {
  data: { status: string; count: number }[] | undefined
  isLoading: boolean
}

const STATUS_COLORS: Record<string, string> = {
  Remediated: '#22c55e',
  Open: '#e53935',
}

export function GvmRemediationPie({ data, isLoading }: GvmRemediationPieProps) {
  const { theme } = useTheme()
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0
  const remediated = data?.find(d => d.status === 'Remediated')?.count || 0

  return (
    <ChartCard
      title="GVM Remediation"
      subtitle={`${remediated} of ${total} remediated`}
      isLoading={isLoading}
      isEmpty={!data?.length}
    >
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data || []}
            dataKey="count"
            nameKey="status"
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={2}
            stroke="none"
          >
            {(data || []).map((entry) => (
              <Cell key={entry.status} fill={STATUS_COLORS[entry.status] || '#71717a'} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
