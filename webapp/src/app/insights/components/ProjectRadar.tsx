'use client'

import { useMemo } from 'react'
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { GraphOverviewData } from '../types'

interface ProjectRadarProps {
  projects: { name: string; data: GraphOverviewData }[]
  isLoading: boolean
}

const METRICS = [
  { key: 'Subdomains', get: (d: GraphOverviewData) => d.subdomainStats.total },
  { key: 'IPs', get: (d: GraphOverviewData) => d.nodeCounts.find(n => n.label === 'IP')?.count || 0 },
  { key: 'Ports', get: (d: GraphOverviewData) => d.nodeCounts.find(n => n.label === 'Port')?.count || 0 },
  { key: 'Endpoints', get: (d: GraphOverviewData) => d.endpointCoverage.endpoints },
  { key: 'Technologies', get: (d: GraphOverviewData) => d.nodeCounts.find(n => n.label === 'Technology')?.count || 0 },
  { key: 'Vulnerabilities', get: (d: GraphOverviewData) => d.nodeCounts.find(n => n.label === 'Vulnerability')?.count || 0 },
]

export function ProjectRadar({ projects, isLoading }: ProjectRadarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!projects.length) return []
    // Normalize each metric to 0-100 scale
    return METRICS.map(m => {
      const row: Record<string, unknown> = { metric: m.key }
      const maxVal = Math.max(...projects.map(p => m.get(p.data)), 1)
      for (const p of projects) {
        row[p.name] = Math.round((m.get(p.data) / maxVal) * 100)
      }
      return row
    })
  }, [projects])

  return (
    <ChartCard title="Project Comparison" subtitle={`${projects.length} projects`} isLoading={isLoading} isEmpty={!projects.length}>
      <ResponsiveContainer width="100%" height={300}>
        <RadarChart data={chartData}>
          <PolarGrid stroke={chrome.gridColor} />
          <PolarAngleAxis dataKey="metric" tick={{ fontSize: 11, fill: chrome.axisColor }} />
          <PolarRadiusAxis tick={false} axisLine={false} />
          {projects.map((p, i) => (
            <Radar
              key={p.name}
              name={p.name}
              dataKey={p.name}
              stroke={palette[i % palette.length]}
              fill={palette[i % palette.length]}
              fillOpacity={0.15}
            />
          ))}
          <Tooltip contentStyle={tooltipStyle} itemStyle={tooltipItemStyle} labelStyle={tooltipLabelStyle} />
          <Legend formatter={(value: string) => <span style={{ fontSize: 11 }}>{value}</span>} />
        </RadarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
