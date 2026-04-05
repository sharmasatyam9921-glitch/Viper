import { NextRequest, NextResponse } from 'next/server'

const VIPER_API = process.env.NEXT_PUBLIC_VIPER_API || 'http://localhost:8080'

// GET /api/projects - Proxy to VIPER Python backend
export async function GET() {
  try {
    const res = await fetch(`${VIPER_API}/api/projects`, { cache: 'no-store' })
    if (res.ok) {
      const data = await res.json()
      // Adapt VIPER format to what the frontend expects
      const projects = (data.projects || []).map((p: any) => ({
        id: String(p.id),
        userId: 'viper-default',
        name: p.name || 'Untitled',
        description: p.notes || '',
        targetDomain: p.target || '',
        createdAt: p.created_at || new Date().toISOString(),
        updatedAt: p.updated_at || new Date().toISOString(),
        user: { id: 'viper-default', name: 'viper-ashborn', email: 'viper@local' }
      }))
      return NextResponse.json(projects)
    }
  } catch (err) {
    console.warn('VIPER projects API unavailable:', err)
  }

  // Fallback: return empty projects list
  return NextResponse.json([])
}

// POST /api/projects - Create project via VIPER backend
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const res = await fetch(`${VIPER_API}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: body.name || 'Untitled',
        target: body.targetDomain || body.target || '',
        notes: body.description || '',
        settings: body.settings || {},
      }),
    })
    if (res.ok) {
      const data = await res.json()
      return NextResponse.json({
        id: String(data.project_id),
        userId: 'viper-default',
        name: body.name,
        targetDomain: body.targetDomain || body.target,
        createdAt: new Date().toISOString(),
      }, { status: 201 })
    }
    return NextResponse.json({ error: 'Failed to create project' }, { status: 500 })
  } catch (error) {
    console.error('Failed to create project:', error)
    return NextResponse.json({ error: 'Failed to create project' }, { status: 500 })
  }
}
