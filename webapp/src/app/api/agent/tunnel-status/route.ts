import { NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function GET() {
  try {
    const resp = await fetch(`${AGENT_API_URL}/tunnel-status`, { cache: 'no-store' })
    if (!resp.ok) {
      return NextResponse.json(
        { ngrok: { active: false }, chisel: { active: false } },
        { status: 200 }
      )
    }
    return NextResponse.json(await resp.json())
  } catch {
    // Fallback: both inactive if agent is unreachable
    return NextResponse.json({ ngrok: { active: false }, chisel: { active: false } })
  }
}
