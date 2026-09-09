import { z } from 'zod'

/**
 * Authenticated remote OOB collector protocol. Day 19 defines the contract
 * only. Twenty-day scope has no real remote service; status is `not-run`.
 * Loopback fixtures must not be labeled as this protocol.
 */
export const RemoteCallbackCollectorStatusSchema = z.enum(['not-run'])

export const RemoteCallbackCollectorProtocolSchema = z
  .strictObject({
    protocolId: z.literal('agentgo.remote-callback-collector/1.0'),
    transport: z.literal('https'),
    authentication: z.enum(['mtls', 'signed-bearer']),
    tenantIsolation: z.literal('required'),
    tls: z.literal('required'),
    replayProtection: z.literal('nonce-and-window'),
    clockSkewToleranceSeconds: z.literal(30),
    status: RemoteCallbackCollectorStatusSchema
  })
  .readonly()

export type RemoteCallbackCollectorProtocol = z.infer<
  typeof RemoteCallbackCollectorProtocolSchema
>

export const REMOTE_CALLBACK_COLLECTOR_PROTOCOL =
  RemoteCallbackCollectorProtocolSchema.parse({
    protocolId: 'agentgo.remote-callback-collector/1.0',
    transport: 'https',
    authentication: 'signed-bearer',
    tenantIsolation: 'required',
    tls: 'required',
    replayProtection: 'nonce-and-window',
    clockSkewToleranceSeconds: 30,
    status: 'not-run'
  })
