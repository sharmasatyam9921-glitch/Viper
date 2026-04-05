import { NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/scan/status`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json({
        recon: data.recon || null,
        gvm: data.gvm || null,
        githubHunt: data.githubHunt || data.github_hunt || null,
      })
    }
  } catch { /* VIPER backend unreachable */ }
  return NextResponse.json({ recon: null, gvm: null, githubHunt: null })
}
