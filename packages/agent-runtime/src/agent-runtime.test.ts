import { LEGACY_V1_FAMILY_IDS } from '@agentgo/contracts'
import { describe, expect, it } from 'vitest'
import {
  SRC_PHASES,
  createDefaultScanPlan,
  createRuntimeState,
  isProbeLevelAllowed,
  nextPhase,
  registerActionResult,
  registerPlanRevision,
  shouldStopForStagnation,
  transitionRuntime
} from './index'

describe('agent runtime workflow', () => {
  it('keeps the gated SRC phases in deterministic order', () => {
    expect(SRC_PHASES.map((phase) => phase.id)).toEqual([
      'intake',
      'passive-recon',
      'active-enum',
      'hypothesis',
      'validation',
      'verification',
      'report'
    ])
    expect(nextPhase('active-enum')).toBe('hypothesis')
  })

  it('never allows destructive probe levels', () => {
    for (const phase of SRC_PHASES) {
      expect(isProbeLevelAllowed(phase.id, 'destructive')).toBe(false)
    }
  })

  it('leaves family defaults to Application and preserves explicit family input', () => {
    const plan = createDefaultScanPlan()
    const legacyPlan = createDefaultScanPlan(LEGACY_V1_FAMILY_IDS)
    const openFamilyPlan = createDefaultScanPlan(['security.headers'])

    expect(plan.families).toEqual([])
    expect(legacyPlan.families).toEqual(LEGACY_V1_FAMILY_IDS)
    expect(openFamilyPlan.families).toEqual(['security.headers'])
    expect(plan.budget.maxPlanRevisions).toBeGreaterThan(0)
    expect(plan.budget.maxRequests).toBeGreaterThan(0)
  })

  it('requires checkpoints to move through the gated workflow', () => {
    const initial = createRuntimeState()
    const scoped = transitionRuntime(initial, {
      type: 'phase-completed',
      checkpointRef: 'scope-checkpoint'
    })

    expect(scoped.phase).toBe('passive-recon')
    expect(scoped.checkpointRefs).toEqual(['scope-checkpoint'])
  })

  it('detects duplicate actions and evidence stagnation', () => {
    const initial = createRuntimeState()
    const first = registerActionResult(initial, 'GET:/search:q=marker', false)
    const second = registerActionResult(first.state, 'GET:/search:q=marker', false)
    const third = registerActionResult(second.state, 'GET:/other', false)

    expect(first.duplicate).toBe(false)
    expect(second.duplicate).toBe(true)
    expect(shouldStopForStagnation(third.state)).toBe(true)
  })

  it('enforces the plan revision budget', () => {
    const plan = createDefaultScanPlan()
    let runtime = createRuntimeState()

    for (let index = 0; index < plan.budget.maxPlanRevisions; index += 1) {
      runtime = registerPlanRevision(runtime, plan)
    }

    expect(() => registerPlanRevision(runtime, plan)).toThrow(
      'Plan revision budget exhausted.'
    )
  })
})
