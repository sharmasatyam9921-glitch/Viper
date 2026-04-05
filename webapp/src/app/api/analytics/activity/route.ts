import { NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/attacks/history`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json({
        project: data.project || { name: '', targetDomain: '', ipMode: '', scanModules: [], createdAt: '', updatedAt: '' },
        conversations: data.conversations || { total: 0, totalIterations: 0, avgIterations: 0, byStatus: [], byPhase: [] },
        remediations: data.remediations || { bySeverity: [], byStatus: [], byCategory: [], exploitableCount: 0 },
        totalMessages: data.totalMessages || 0,
        timeline: data.timeline || { conversations: [], remediations: [] },
      })
    }
  } catch { /* VIPER backend unreachable */ }
  return NextResponse.json({
    project: { name: '', targetDomain: '', ipMode: '', scanModules: [], createdAt: '', updatedAt: '' },
    conversations: { total: 0, totalIterations: 0, avgIterations: 0, byStatus: [], byPhase: [] },
    remediations: { bySeverity: [], byStatus: [], byCategory: [], exploitableCount: 0 },
    totalMessages: 0,
    timeline: { conversations: [], remediations: [] },
  })
}
