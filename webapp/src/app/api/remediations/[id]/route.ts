import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/remediations/[id] - Get single remediation
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const remediation = await prisma.remediation.findUnique({
      where: { id },
    })

    if (!remediation) {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(remediation)
  } catch (error) {
    console.error('Failed to fetch remediation:', error)
    return NextResponse.json(
      { error: 'Failed to fetch remediation' },
      { status: 500 }
    )
  }
}

// PUT /api/remediations/[id] - Update remediation
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const { projectId, createdAt, updatedAt, project, ...updateData } = body

    const remediation = await prisma.remediation.update({
      where: { id },
      data: updateData,
    })

    return NextResponse.json(remediation)
  } catch (error: unknown) {
    console.error('Failed to update remediation:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update remediation' },
      { status: 500 }
    )
  }
}

// DELETE /api/remediations/[id] - Delete remediation
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    await prisma.remediation.delete({
      where: { id },
    })

    return NextResponse.json({ success: true })
  } catch (error: unknown) {
    console.error('Failed to delete remediation:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to delete remediation' },
      { status: 500 }
    )
  }
}
