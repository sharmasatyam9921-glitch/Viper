import { NextResponse } from 'next/server'

// VIPER runs in single-user mode — no PostgreSQL needed
export async function GET() {
  return NextResponse.json([
    {
      id: 'viper-default',
      name: 'viper-ashborn',
      email: 'viper@local',
      createdAt: new Date().toISOString(),
      _count: { projects: 1 }
    }
  ])
}

export async function POST() {
  return NextResponse.json({
    id: 'viper-default',
    name: 'viper-ashborn',
    email: 'viper@local',
  }, { status: 201 })
}
