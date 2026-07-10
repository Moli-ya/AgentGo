import { describe, expect, it } from 'vitest'
import { DesktopOutputSchemas, PolicySelfCheckResultSchema } from './desktop'

describe('desktop IPC output contracts', () => {
  it('validates and strips fields outside the renderer contract', () => {
    const parsed = DesktopOutputSchemas.workspace.parse({
      id: 'workspace-1',
      name: 'Authorized lab',
      description: '',
      createdAt: '2026-07-10T00:00:00.000Z',
      updatedAt: '2026-07-10T00:00:00.000Z',
      internalSecret: 'must-not-cross-ipc'
    })

    expect(parsed).not.toHaveProperty('internalSecret')
  })

  it('rejects an unknown policy decision code before it reaches the renderer', () => {
    const result = PolicySelfCheckResultSchema.safeParse({
      safeProbe: {
        allowed: true,
        requiresApproval: false,
        code: 'invented-code',
        reasons: []
      },
      destructiveProbe: {
        allowed: false,
        requiresApproval: false,
        code: 'destructive-action',
        reasons: ['blocked']
      },
      note: 'local check'
    })

    expect(result.success).toBe(false)
  })
})
