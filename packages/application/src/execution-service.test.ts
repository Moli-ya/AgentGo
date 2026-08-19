import { describe, expect, expectTypeOf, it } from 'vitest'
import type { ExecutionPort } from './execution-port'
import { ExecutionService } from './execution-service'

describe('ExecutionService public boundary', () => {
  it('implements only the unified ExecutionPort entry point', () => {
    expectTypeOf<ExecutionService>().toMatchTypeOf<ExecutionPort>()

    const prototype = ExecutionService.prototype as unknown as Record<
      string,
      unknown
    >
    expect(typeof prototype.execute).toBe('function')
    expect(Object.prototype.hasOwnProperty.call(prototype, 'executeHttp')).toBe(
      false
    )
    expect(
      Object.prototype.hasOwnProperty.call(prototype, 'executeBrowser')
    ).toBe(false)
  })

  it('requires one dependency object instead of legacy runner arguments', () => {
    expect(ExecutionService.length).toBe(1)
  })
})
