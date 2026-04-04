'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface IpConcentrationBarProps {
  data: { ip: string; subCount: number; isCdn: boolean }[] | undefined
  isLoading: boolean
}

export function IpConcentrationBar({ data, isLoading }: IpConcentrationBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  return (
    <ChartCard
      title="IP Concentration"
      subtitle={`Subdomains per IP · ${data?.length || 0} IPs`}
      isLoading={isLoading}
      isEmpty={!data?.length}
    >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data || []} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="ip"
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={105}
          />
          <Tooltip
            cursor={cursorStyle}
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _: string, props: { payload?: { isCdn: boolean } }) => [
              value,
              `Subdomains${props.payload?.isCdn ? ' (CDN)' : ''}`,
            ]}
          />
          <Bar dataKey="subCount" radius={[0, 4, 4, 0]} maxBarSize={16} name="Subdomains">
            {(data || []).map((entry) => (
              <Cell key={entry.ip} fill={entry.isCdn ? '#f97316' : '#3b82f6'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
