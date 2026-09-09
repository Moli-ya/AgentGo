import { describe, expect, it } from 'vitest'
import {
  REMOTE_CALLBACK_COLLECTOR_PROTOCOL,
  RemoteCallbackCollectorProtocolSchema
} from './remote-callback-collector'

describe('remote callback collector protocol', () => {
  it('defines authenticated TLS tenant isolation and remains not-run', () => {
    expect(REMOTE_CALLBACK_COLLECTOR_PROTOCOL).toMatchObject({
      protocolId: 'agentgo.remote-callback-collector/1.0',
      transport: 'https',
      tls: 'required',
      tenantIsolation: 'required',
      replayProtection: 'nonce-and-window',
      status: 'not-run'
    })
    expect(
      RemoteCallbackCollectorProtocolSchema.parse({
        ...REMOTE_CALLBACK_COLLECTOR_PROTOCOL,
        status: 'not-run'
      }).status
    ).toBe('not-run')
  })
})
