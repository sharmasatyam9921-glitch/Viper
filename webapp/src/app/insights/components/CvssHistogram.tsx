'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface CvssHistogramProps {
  data: { bucket: number; count: number }[] | undefined
  isLoading: boolean
}

function bucketColor(bucket: number): string {
  if (bucket >= 9) return '#e53935'
  if (bucket >= 7) return '#f97316'
  if (bucket >= 4) return '#f59e0b'
  if (bucket >= 1) return '#3b82f6'
  return '#a1a1aa'
}

export function CvssHistogram({ data, isLoading }: CvssHistogramProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data) return []
    const buckets = Array.from({ length: 11 }, (_, i) => ({ bucket: i, count: 0, label: `${i}` }))
    for (const d of data) {
      const idx = Math.min(Math.max(0, d.bucket), 10)
      buckets[idx].count += d.count
    }
    return buckets
  }, [data])

  const total = chartData.reduce((s, d) => s + d.count, 0)

  return (
    <ChartCard title="CVSS Score Distribution" subtitle={`${total} CVEs`} isLoading={isLoading} isEmpty={total === 0}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="label"
            tick={{ fontSize: 11, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} width={35} />
          <Tooltip cursor={cursorStyle} contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={28}>
            {chartData.map((entry) => (
              <Cell key={entry.bucket} fill={bucketColor(entry.bucket)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
