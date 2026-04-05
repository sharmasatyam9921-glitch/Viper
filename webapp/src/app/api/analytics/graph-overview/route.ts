import { NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

const EMPTY = {
  nodeCounts: [],
  relationshipCounts: [],
  totalNodes: 0,
  totalRelationships: 0,
  subdomainStats: { total: 0, resolved: 0, uniqueIps: 0 },
  endpointCoverage: { baseUrls: 0, endpoints: 0, parameters: 0 },
  certificateHealth: { total: 0, expired: 0, expiringSoon: 0 },
  topConnected: [],
  infrastructureStats: { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 },
}

export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/graph`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json({ ...EMPTY, ...data })
    }
  } catch { /* VIPER backend unreachable */ }
  return NextResponse.json(EMPTY)
}
