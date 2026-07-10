import { describe, expect, it } from 'vitest'
import { redactSensitiveText } from './index'

describe('model input redaction', () => {
  it('removes bearer tokens and API keys before provider calls', () => {
    const redacted = redactSensitiveText(
      'Authorization: Bearer secret-token api_key=top-secret'
    )

    expect(redacted).not.toContain('secret-token')
    expect(redacted).not.toContain('top-secret')
    expect(redacted).toContain('[REDACTED]')
  })
})
