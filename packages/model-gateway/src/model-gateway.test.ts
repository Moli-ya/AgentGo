import { describe, expect, it } from 'vitest'
import {
  DefaultModelGateway,
  redactModelInput,
  redactSensitiveText,
  type ModelInvocationInput,
  type ModelProfile
} from './index'

describe('model input redaction', () => {
  it('removes bearer tokens and API keys before provider calls', () => {
    const redacted = redactSensitiveText(
      'Authorization: Bearer secret-token api_key=top-secret'
    )

    expect(redacted).not.toContain('secret-token')
    expect(redacted).not.toContain('top-secret')
    expect(redacted).toContain('[REDACTED]')
  })

  it('redacts nested secret fields without mutating the source object', () => {
    const input = { request: { authorization: 'Bearer nested-secret', value: 'safe' } }
    const redacted = redactModelInput(input)

    expect(redacted).toEqual({
      request: { authorization: '[REDACTED]', value: 'safe' }
    })
    expect(input.request.authorization).toBe('Bearer nested-secret')
  })
})

describe('DefaultModelGateway', () => {
  const profile: ModelProfile = {
    id: 'deterministic-planner',
    name: 'Deterministic Planner',
    agentRole: 'planner',
    provider: 'deterministic',
    model: 'agentgo-rules-v1',
    timeoutMs: 1_000,
    rpmLimit: 30,
    tpmLimit: 10_000,
    tokenBudget: 100_000,
    costBudget: 0
  }

  it('validates deterministic structured output and records redacted invocation metadata', async () => {
    let invocation: ModelInvocationInput | undefined
    const gateway = new DefaultModelGateway({
      profiles: { getModelProfile: async () => profile },
      credentials: { get: () => undefined },
      prompts: {
        getPrompt: () => ({
          id: 'planner',
          version: '1.0.0',
          system: 'Return a safe plan.',
          deterministic: (input) => ({
            accepted: (input as { authorization: string }).authorization === '[REDACTED]'
          })
        })
      },
      invocations: {
        recordModelInvocation: async (input) => {
          invocation = input
        }
      }
    })

    const result = await gateway.structuredCompletion({
      profileId: profile.id,
      systemPromptId: 'planner',
      systemPromptVersion: '1.0.0',
      input: { authorization: 'Bearer should-not-leak' },
      schema: {
        parse: (value) => {
          if (
            !value ||
            typeof value !== 'object' ||
            (value as { accepted?: unknown }).accepted !== true
          ) {
            throw new Error('Invalid deterministic result.')
          }
          return value as { accepted: true }
        }
      },
      agentRunId: 'run-1'
    })

    expect(result.value.accepted).toBe(true)
    expect(result.provider).toBe('deterministic')
    expect(invocation?.inputHashSource).not.toContain('should-not-leak')
  })

  it('tests an external profile through a real chat/completions request shape', async () => {
    const externalProfile: ModelProfile = {
      ...profile,
      id: 'external-planner-connection',
      provider: 'openai-compatible',
      baseUrl: 'https://provider.example.test/v1/',
      credentialId: 'provider-key',
      model: 'structured-model'
    }
    let requestedUrl = ''
    let requestBody = ''
    const gateway = new DefaultModelGateway({
      profiles: { getModelProfile: async () => externalProfile },
      credentials: { get: () => 'test-api-key' },
      prompts: { getPrompt: () => undefined },
      fetchImplementation: async (input, init) => {
        requestedUrl = String(input)
        requestBody = String(init?.body ?? '')
        return new Response(
          JSON.stringify({
            model: 'structured-model',
            choices: [{ message: { content: '{"ok":true}' } }]
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      }
    })

    const result = await gateway.testConnection(externalProfile.id)
    const payload = JSON.parse(requestBody) as {
      model: string
      response_format: { type: string }
      messages: Array<{ role: string; content: string }>
    }

    expect(result.ok).toBe(true)
    expect(result.message).toContain('真实 chat/completions 调用成功')
    expect(requestedUrl).toBe('https://provider.example.test/v1/chat/completions')
    expect(payload.model).toBe('structured-model')
    expect(payload.response_format).toEqual({ type: 'json_object' })
    expect(payload.messages.some((message) => message.content.includes('{"ok":true}'))).toBe(
      true
    )
  })

  it('accumulates provider-reported cost and rejects calls beyond the profile budget', async () => {
    const externalProfile: ModelProfile = {
      ...profile,
      id: 'external-planner',
      provider: 'openai-compatible',
      baseUrl: 'https://provider.example.test/v1/',
      credentialId: 'provider-key',
      model: 'structured-model',
      costBudget: 0.01
    }
    const gateway = new DefaultModelGateway({
      profiles: { getModelProfile: async () => externalProfile },
      credentials: { get: () => 'test-api-key' },
      prompts: {
        getPrompt: () => ({
          id: 'planner',
          version: '1.0.0',
          system: 'Return JSON.'
        })
      },
      fetchImplementation: async () =>
        new Response(
          JSON.stringify({
            model: 'structured-model',
            choices: [{ message: { content: '{"accepted":true}' } }],
            usage: { prompt_tokens: 10, completion_tokens: 5, cost: 0.004 }
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
    })
    const request = {
      profileId: externalProfile.id,
      systemPromptId: 'planner',
      systemPromptVersion: '1.0.0',
      input: { task: 'safe' },
      schema: {
        parse: (value: unknown) => value as { accepted: true }
      }
    }

    const first = await gateway.structuredCompletion(request)
    const second = await gateway.structuredCompletion(request)

    expect(first.estimatedCost).toBe(0.004)
    expect(second.estimatedCost).toBe(0.004)
    await expect(gateway.structuredCompletion(request)).rejects.toThrow(
      'cost budget is exhausted'
    )
  })
})
