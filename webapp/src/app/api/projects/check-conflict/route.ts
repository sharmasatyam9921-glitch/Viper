import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface ConflictCheckRequest {
  targetDomain: string
  subdomainList: string[]
  ipMode?: boolean
  excludeProjectId?: string  // For edit mode - exclude current project from check
}

interface ConflictResult {
  hasConflict: boolean
  conflictType: 'full_scan_exists' | 'full_scan_requested' | 'subdomain_overlap' | null
  conflictingProject: {
    id: string
    name: string
    targetDomain: string
    subdomainList: string[]
  } | null
  overlappingSubdomains: string[]
  message: string | null
}

const NO_CONFLICT: ConflictResult = {
  hasConflict: false,
  conflictType: null,
  conflictingProject: null,
  overlappingSubdomains: [],
  message: null,
}

// POST /api/projects/check-conflict - Check if a project would conflict with existing ones
export async function POST(request: NextRequest): Promise<NextResponse<ConflictResult>> {
  try {
    const body: ConflictCheckRequest = await request.json()
    const { targetDomain, subdomainList, ipMode, excludeProjectId } = body

    // IP mode: no conflict check needed — tenant-scoped Neo4j constraints
    // allow the same IP across different projects
    if (ipMode) {
      return NextResponse.json(NO_CONFLICT)
    }

    // Domain mode conflict check
    if (!targetDomain) {
      return NextResponse.json(NO_CONFLICT)
    }

    // Normalize domain (lowercase, trim)
    const normalizedDomain = targetDomain.toLowerCase().trim()

    // Find all projects with the same target domain
    const existingProjects = await prisma.project.findMany({
      where: {
        targetDomain: {
          equals: normalizedDomain,
          mode: 'insensitive',
        },
        ipMode: false,
        ...(excludeProjectId ? { id: { not: excludeProjectId } } : {}),
      },
      select: {
        id: true,
        name: true,
        targetDomain: true,
        subdomainList: true,
      },
    })

    if (existingProjects.length === 0) {
      return NextResponse.json(NO_CONFLICT)
    }

    // Normalize new project's subdomain list
    const newSubdomains = (subdomainList || []).map(s => s.toLowerCase().trim()).filter(Boolean)
    const isNewFullScan = newSubdomains.length === 0

    // Check for conflicts
    for (const existing of existingProjects) {
      const existingSubdomains = (existing.subdomainList || []).map((s: string) => s.toLowerCase().trim()).filter(Boolean)
      const isExistingFullScan = existingSubdomains.length === 0

      // Case 1: Existing project scans ALL subdomains (full scan)
      if (isExistingFullScan) {
        return NextResponse.json({
          hasConflict: true,
          conflictType: 'full_scan_exists',
          conflictingProject: existing,
          overlappingSubdomains: [],
          message: `Project "${existing.name}" already scans all subdomains of ${existing.targetDomain}. You cannot create another project for this domain.`,
        })
      }

      // Case 2: New project wants to scan ALL subdomains but existing projects have specific subdomains
      if (isNewFullScan) {
        return NextResponse.json({
          hasConflict: true,
          conflictType: 'full_scan_requested',
          conflictingProject: existing,
          overlappingSubdomains: existingSubdomains,
          message: `Cannot scan all subdomains of ${normalizedDomain}. Project "${existing.name}" already scans specific subdomains: ${existingSubdomains.join(', ')}`,
        })
      }

      // Case 3: Both have specific subdomains - check for overlap
      const overlapping = newSubdomains.filter(sub => existingSubdomains.includes(sub))
      if (overlapping.length > 0) {
        return NextResponse.json({
          hasConflict: true,
          conflictType: 'subdomain_overlap',
          conflictingProject: existing,
          overlappingSubdomains: overlapping,
          message: `Subdomain conflict with project "${existing.name}". Overlapping subdomains: ${overlapping.join(', ')}`,
        })
      }
    }

    // No conflicts found
    return NextResponse.json(NO_CONFLICT)

  } catch (error) {
    console.error('Failed to check project conflict:', error)
    return NextResponse.json(
      {
        hasConflict: false,
        conflictType: null,
        conflictingProject: null,
        overlappingSubdomains: [],
        message: 'Failed to check for conflicts',
      },
      { status: 500 }
    )
  }
}
