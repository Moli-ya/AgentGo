import { describe, expect, it } from 'vitest'
import {
  assessIdor,
  assessSqli,
  assessSsrf,
  assessXss,
  type BrowserObservation,
  type HttpObservation
} from './validation-engine'

let counter = 0

function observation(body: string, statusCode = 200): HttpObservation {
  counter += 1
  return {
    result: {
      status: 'succeeded',
      statusCode,
      responseBody: Buffer.from(body),
      responseBodySha256: `hash-${counter}`,
      responseBytes: Buffer.byteLength(body),
      durationMs: 10,
      responseHeaders: { 'content-type': 'text/plain' }
    },
    evidenceRefs: [`evidence-${counter}`],
    interactionId: `interaction-${counter}`,
    toolCallId: `tool-${counter}`,
    proposalId: `proposal-${counter}`,
    policyDecisionId: `decision-${counter}`
  }
}

describe('V1 deterministic confirmation rules', () => {
  it('confirms repeatable SQLi boolean differential with a negative control', () => {
    const result = assessSqli({
      baseline: observation('product: visible'),
      trueFirst: observation('product: visible'),
      falseControl: observation('no rows'),
      trueRepeat: observation('product: visible')
    })

    expect(result.verdict).toBe('confirmed')
    expect(result.failedChecks).toEqual([])
  })

  it('does not treat XSS reflection as execution', () => {
    const marker = 'agx_0011223344556677'
    const http = observation(`<p>${marker}</p>`)
    const browser: BrowserObservation = {
      result: {
        requestId: 'browser-1',
        status: 'succeeded',
        finalUrl: 'https://lab.test/',
        links: [],
        forms: [],
        markerExecuted: false,
        networkRequestsBlocked: 0,
        durationMs: 20
      },
      evidenceRefs: ['browser-summary', 'dom-snapshot'],
      toolCallId: 'tool-browser',
      proposalId: 'proposal-browser',
      policyDecisionId: 'decision-browser'
    }

    expect(assessXss({ marker, http, browser }).verdict).toBe('not-confirmed')
    browser.result.markerExecuted = true
    expect(assessXss({ marker, http, browser }).verdict).toBe('confirmed')
  })

  it('confirms SSRF only when controlled proof is relayed and absent in negative control', () => {
    const proof = 'AGENTGO_CALLBACK_PROOF_12345678'
    const result = assessSsrf({
      callbackBaseline: observation(proof),
      targetProbe: observation(`fetched:${proof}`),
      negativeControl: observation('invalid url')
    })

    expect(result.verdict).toBe('confirmed')
  })

  it('confirms read-only IDOR only with two authorized identities and known ownership', () => {
    const result = assessIdor({
      ownerResourceId: 'resource-a',
      secondIdentityResourceId: 'resource-b',
      ownerRead: observation('{"id":"resource-a","secret":"test-only"}'),
      secondIdentityOwnRead: observation('{"id":"resource-b","secret":"test-only-b"}'),
      secondIdentityOwnerRead: observation('{"id":"resource-a","secret":"test-only"}'),
      identitiesAuthorized: true
    })

    expect(result.verdict).toBe('confirmed')
  })
})
