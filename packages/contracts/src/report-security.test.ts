import { describe, expect, it } from 'vitest'
import { GenerateReportInputSchema } from './application'

describe('report persistence security', () => {
  it('rejects requests to persist or export an unredacted report', () => {
    expect(
      GenerateReportInputSchema.safeParse({
        scanId: '10000000-0000-4000-8000-000000000001',
        format: 'markdown',
        redacted: false
      }).success
    ).toBe(false)
    expect(
      GenerateReportInputSchema.parse({
        scanId: '10000000-0000-4000-8000-000000000001',
        format: 'markdown'
      }).redacted
    ).toBe(true)
  })
})
