import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { readFile, stat, open } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'
const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    if (!PROJECT_ID_RE.test(projectId)) {
      return new NextResponse(null, { status: 400 })
    }

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, name: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // JS Recon data is inside the main recon JSON under the 'js_recon' key,
    // but also check for standalone output file
    const standaloneFile = path.join(RECON_OUTPUT_PATH, `js_recon_${projectId}.json`)
    const reconFile = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)

    let jsReconData = null

    // Try standalone file first
    if (existsSync(standaloneFile)) {
      const content = await readFile(standaloneFile, 'utf-8')
      jsReconData = content
    }
    // Fall back to extracting from main recon JSON
    else if (existsSync(reconFile)) {
      const fileStat = await stat(reconFile)
      // Guard against extremely large files (>100MB)
      if (fileStat.size > 100 * 1024 * 1024) {
        return NextResponse.json(
          { error: 'Recon file too large for extraction. Run JS Recon standalone to generate a separate output file.' },
          { status: 413 }
        )
      }
      const content = await readFile(reconFile, 'utf-8')
      try {
        const reconData = JSON.parse(content)
        if (reconData.js_recon) {
          jsReconData = JSON.stringify(reconData.js_recon, null, 2)
        }
      } catch {
        // Invalid JSON
      }
    }

    if (!jsReconData) {
      return NextResponse.json(
        { error: 'JS Recon data not found. Run a JS Recon scan first.' },
        { status: 404 }
      )
    }

    const jsonFileName = `js_recon_${projectId}.json`

    return new NextResponse(jsReconData, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${jsonFileName}"`,
        'Cache-Control': 'no-cache',
      },
    })
  } catch (error) {
    console.error('Error downloading JS Recon data:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    if (!PROJECT_ID_RE.test(projectId)) {
      return new NextResponse(null, { status: 400 })
    }

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return new NextResponse(null, { status: 404 })
    }

    const standaloneFile = path.join(RECON_OUTPUT_PATH, `js_recon_${projectId}.json`)
    const reconFile = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)

    if (existsSync(standaloneFile)) {
      return new NextResponse(null, { status: 200 })
    }

    if (existsSync(reconFile)) {
      // Read only first 16KB to check for js_recon key (avoids loading entire file)
      try {
        const fd = await open(reconFile, 'r')
        const buffer = Buffer.alloc(16384)
        await fd.read(buffer, 0, 16384, 0)
        await fd.close()
        // js_recon key appears early in the JSON if present (in metadata.modules_executed or as top-level key)
        if (buffer.toString('utf-8').includes('"js_recon"')) {
          return new NextResponse(null, { status: 200 })
        }
      } catch {
        // Fall back to full read if partial read fails
        const content = await readFile(reconFile, 'utf-8')
        if (content.includes('"js_recon"')) {
          return new NextResponse(null, { status: 200 })
        }
      }
    }

    return new NextResponse(null, { status: 404 })
  } catch {
    return new NextResponse(null, { status: 500 })
  }
}
