'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { SecurityFinding } from '../types'

interface VulnSourcePieProps {
  data: SecurityFinding[] | undefined
  isLoading: boolean
}

const SOURCE_COLORS: Record<string, string> = {
  nuclei: '#3b82f6',
  gvm: '#f97316',
  security_check: '#22c55e',
}

export function VulnSourcePie({ data, isLoading }: VulnSourcePieProps) {
  const { theme } = useTheme()
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const map = new Map<string, number>()
    for (const f of data) {
      const src = f.source || 'unknown'
      map.set(src, (map.get(src) || 0) + 1)
    }
    return [...map.entries()]
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count)
  }, [data])

  const total = data?.length || 0

  return (
    <ChartCard title="Vulnerability Sources" subtitle={`${total} findings`} isLoading={isLoading} isEmpty={!chartData.length}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="count"
            nameKey="source"
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={2}
            stroke="none"
          >
            {chartData.map((entry) => (
              <Cell key={entry.source} fill={SOURCE_COLORS[entry.source] || '#71717a'} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
