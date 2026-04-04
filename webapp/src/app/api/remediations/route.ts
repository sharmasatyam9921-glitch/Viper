import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// GET /api/remediations?projectId=X - List remediations for project
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const projectId = searchParams.get('projectId')

    if (!projectId) {
      return NextResponse.json(
        { error: 'projectId is required' },
        { status: 400 }
      )
    }

    const status = searchParams.get('status')
    const severity = searchParams.get('severity')
    const sort = searchParams.get('sort') || 'priority'
    const order = (searchParams.get('order') || 'asc') as 'asc' | 'desc'

    const where: Record<string, unknown> = { projectId }
    if (status) where.status = status
    if (severity) where.severity = severity

    const remediations = await prisma.remediation.findMany({
      where,
      orderBy: { [sort]: order },
    })

    return NextResponse.json(remediations)
  } catch (error) {
    console.error('Failed to fetch remediations:', error)
    return NextResponse.json(
      { error: 'Failed to fetch remediations' },
      { status: 500 }
    )
  }
}

// POST /api/remediations - Create a single remediation
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, title, description, ...rest } = body

    if (!projectId || !title || !description) {
      return NextResponse.json(
        { error: 'projectId, title, and description are required' },
        { status: 400 }
      )
    }

    const remediation = await prisma.remediation.create({
      data: { projectId, title, description, ...rest },
    })

    return NextResponse.json(remediation, { status: 201 })
  } catch (error) {
    console.error('Failed to create remediation:', error)
    return NextResponse.json(
      { error: 'Failed to create remediation' },
      { status: 500 }
    )
  }
}
