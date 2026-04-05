import { NextRequest, NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

// GET /api/conversations - Proxy to VIPER chat history
export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/chat/history`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json(data.conversations || [])
    }
  } catch {}
  return NextResponse.json([])
}

// POST /api/conversations - Create conversation (proxy to VIPER)
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const res = await fetch(`${VIPER_API}/api/chat/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (res.ok) return NextResponse.json(await res.json(), { status: 201 })
  } catch {}
  return NextResponse.json({ id: Date.now().toString(), messages: [] }, { status: 201 })
}
