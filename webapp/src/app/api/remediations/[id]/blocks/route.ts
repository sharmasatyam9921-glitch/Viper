import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// PUT /api/remediations/[id]/blocks - Update individual block statuses
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()
    const { fileChanges } = body

    if (!fileChanges) {
      return NextResponse.json(
        { error: 'fileChanges is required' },
        { status: 400 }
      )
    }

    const remediation = await prisma.remediation.update({
      where: { id },
      data: { fileChanges },
    })

    return NextResponse.json(remediation)
  } catch (error: unknown) {
    console.error('Failed to update block statuses:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update block statuses' },
      { status: 500 }
    )
  }
}
