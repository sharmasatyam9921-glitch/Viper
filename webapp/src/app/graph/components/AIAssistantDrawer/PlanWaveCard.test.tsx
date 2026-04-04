/**
 * Unit tests for PlanWaveCard and plan wave timeline integration.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/PlanWaveCard.test.tsx
 */

import { describe, test, expect } from 'vitest'
import type { PlanWaveItem, ToolExecutionItem } from './AgentTimeline'

// ---------------------------------------------------------------------------
// PlanWaveItem type construction tests
// ---------------------------------------------------------------------------

function makeTool(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: `tool-${Date.now()}`,
    timestamp: new Date(),
    tool_name: 'execute_nmap',
    tool_args: { target: '10.0.0.1' },
    status: 'running',
    output_chunks: [],
    ...overrides,
  }
}

function makeWave(overrides: Partial<PlanWaveItem> = {}): PlanWaveItem {
  return {
    type: 'plan_wave',
    id: `wave-${Date.now()}`,
    timestamp: new Date(),
    wave_id: 'wave-3-abc12345',
    plan_rationale: 'Independent recon tools',
    tool_count: 2,
    tools: [],
    status: 'running',
    ...overrides,
  }
}

describe('PlanWaveItem type', () => {
  test('creates valid empty wave', () => {
    const wave = makeWave()
    expect(wave.type).toBe('plan_wave')
    expect(wave.tools).toHaveLength(0)
    expect(wave.status).toBe('running')
  })

  test('creates wave with nested tools', () => {
    const wave = makeWave({
      tools: [
        makeTool({ tool_name: 'execute_nmap', status: 'success' }),
        makeTool({ tool_name: 'query_graph', status: 'running' }),
      ],
    })
    expect(wave.tools).toHaveLength(2)
    expect(wave.tools[0].tool_name).toBe('execute_nmap')
    expect(wave.tools[1].tool_name).toBe('query_graph')
  })
})

// ---------------------------------------------------------------------------
// Status calculation logic (same as PlanWaveCard component)
// ---------------------------------------------------------------------------

function computeWaveStats(wave: PlanWaveItem) {
  const completedCount = wave.tools.filter(t => t.status !== 'running').length
  const successCount = wave.tools.filter(t => t.status === 'success').length
  return { completedCount, successCount }
}

describe('Wave status computation', () => {
  test('all running = 0 completed', () => {
    const wave = makeWave({
      tools: [
        makeTool({ status: 'running' }),
        makeTool({ status: 'running' }),
      ],
    })
    const { completedCount, successCount } = computeWaveStats(wave)
    expect(completedCount).toBe(0)
    expect(successCount).toBe(0)
  })

  test('all success', () => {
    const wave = makeWave({
      tools: [
        makeTool({ status: 'success' }),
        makeTool({ status: 'success' }),
      ],
    })
    const { completedCount, successCount } = computeWaveStats(wave)
    expect(completedCount).toBe(2)
    expect(successCount).toBe(2)
  })

  test('mixed success and error', () => {
    const wave = makeWave({
      tools: [
        makeTool({ status: 'success' }),
        makeTool({ status: 'error' }),
      ],
    })
    const { completedCount, successCount } = computeWaveStats(wave)
    expect(completedCount).toBe(2)
    expect(successCount).toBe(1)
  })

  test('one running, one complete', () => {
    const wave = makeWave({
      tools: [
        makeTool({ status: 'success' }),
        makeTool({ status: 'running' }),
      ],
    })
    const { completedCount, successCount } = computeWaveStats(wave)
    expect(completedCount).toBe(1)
    expect(successCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Plan complete status derivation (same as AIAssistantDrawer handler)
// ---------------------------------------------------------------------------

function derivePlanStatus(failed: number, total: number): PlanWaveItem['status'] {
  if (failed === total) return 'error'
  if (failed > 0) return 'partial'
  return 'success'
}

describe('Plan complete status derivation', () => {
  test('0 failed = success', () => {
    expect(derivePlanStatus(0, 3)).toBe('success')
  })

  test('some failed = partial', () => {
    expect(derivePlanStatus(1, 3)).toBe('partial')
  })

  test('all failed = error', () => {
    expect(derivePlanStatus(3, 3)).toBe('error')
  })

  test('0 total, 0 failed = success', () => {
    expect(derivePlanStatus(0, 0)).toBe('success')
  })
})

// ---------------------------------------------------------------------------
// History reconstruction: immutable wave nesting
// ---------------------------------------------------------------------------

describe('Wave nesting (immutable)', () => {
  test('nesting tool into wave creates new object', () => {
    const wave = makeWave({ tools: [] })
    const items: (PlanWaveItem | ToolExecutionItem)[] = [wave]

    // Simulate immutable nesting (same as AIAssistantDrawer post-pass)
    const newTool = makeTool({ id: 'nested-1', tool_name: 'execute_nmap', status: 'success' })
    const updatedWave = { ...wave, tools: [...wave.tools, newTool] }
    items[0] = updatedWave

    // Original wave unchanged
    expect(wave.tools).toHaveLength(0)
    // Updated wave has the tool
    expect(updatedWave.tools).toHaveLength(1)
    expect(updatedWave.tools[0].id).toBe('nested-1')
  })

  test('status update creates new object', () => {
    const wave = makeWave({ status: 'running' })
    const updated = { ...wave, status: 'success' as const }

    expect(wave.status).toBe('running')
    expect(updated.status).toBe('success')
  })
})

// ---------------------------------------------------------------------------
// Wave ID matching
// ---------------------------------------------------------------------------

describe('wave_id matching', () => {
  test('finds wave by wave_id', () => {
    const items: PlanWaveItem[] = [
      makeWave({ wave_id: 'wave-1-aaa' }),
      makeWave({ wave_id: 'wave-2-bbb' }),
    ]
    const found = items.find(i => i.wave_id === 'wave-2-bbb')
    expect(found).toBeDefined()
    expect(found!.wave_id).toBe('wave-2-bbb')
  })

  test('returns undefined for missing wave_id', () => {
    const items: PlanWaveItem[] = [
      makeWave({ wave_id: 'wave-1-aaa' }),
    ]
    const found = items.find(i => i.wave_id === 'wave-99-zzz')
    expect(found).toBeUndefined()
  })
})
