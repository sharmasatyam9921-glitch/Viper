'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface CdnVsDirectPieProps {
  data: { segment: string; count: number }[] | undefined
  isLoading: boolean
}

export function CdnVsDirectPie({ data, isLoading }: CdnVsDirectPieProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const total = data?.reduce((s, d) => s + d.count, 0) || 0

  return (
    <ChartCard title="CDN Coverage" subtitle={`${total} IPs`} isLoading={isLoading} isEmpty={!data?.length}>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data || []}
            dataKey="count"
            nameKey="segment"
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={2}
            stroke="none"
          >
            {(data || []).map((entry, i) => (
              <Cell
                key={entry.segment}
                fill={entry.segment === 'Direct (No CDN)' ? '#22c55e' : palette[i % palette.length]}
              />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
