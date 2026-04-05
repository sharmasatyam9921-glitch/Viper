import { NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

const EMPTY = {
  chains: [],
  chainToolUsage: [],
  chainSuccessRate: [],
  findingsByType: [],
  findingsBySeverity: [],
  phaseProgression: [],
  exploitSuccesses: [],
  topFindings: [],
  failuresByType: [],
  decisions: [],
  gvmExploits: [],
  targetsAttacked: [],
  attackFlowRows: [],
}

export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/attacks/kill-chain`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json({ ...EMPTY, ...data })
    }
  } catch { /* VIPER backend unreachable */ }
  return NextResponse.json(EMPTY)
}
