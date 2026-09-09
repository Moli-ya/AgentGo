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

  it('normalizes volatile response fields before boolean comparison', () => {
    const result = assessSqli({
      baseline: observation('product id=1234567 at 2026-09-07T10:00:00Z'),
      trueFirst: observation('product id=7654321 at 2026-09-07T10:01:00Z'),
      falseControl: observation('no rows'),
      trueRepeat: observation('product id=9999999 at 2026-09-07T10:02:00Z')
    })

    expect(result.verdict).toBe('confirmed')
    expect(result.signalSummary).toContain('sqli.normalize@1.1.0')
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
        resultBytes: 0,
        durationMs: 20
      },
      evidenceRefs: ['browser-summary', 'dom-snapshot'],
      toolCallId: 'tool-browser',
      proposalId: 'proposal-browser',
      policyDecisionId: 'decision-browser'
    }

    expect(assessXss({ marker, http, browser }).verdict).toBe('not-confirmed')
    const executedBrowser: BrowserObservation = {
      ...browser,
      result: { ...browser.result, markerExecuted: true }
    }
    const executedWithoutReviewableEvidence = assessXss({
      marker,
      http,
      browser: executedBrowser
    })
    expect(executedWithoutReviewableEvidence.verdict).toBe('inconclusive')
    expect(executedWithoutReviewableEvidence.explanation).toContain(
      '缺少可审阅的 DOM/截图证据'
    )
    const reviewedBrowser: BrowserObservation = {
      ...executedBrowser,
      reviewableDomOrScreenshotEvidence: true
    }
    expect(assessXss({ marker, http, browser: reviewedBrowser }).verdict).toBe(
      'confirmed'
    )
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

  it('does not confirm shared-object IDOR and treats session/dynamic evidence as inconclusive', () => {
    const shared = assessIdor({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead: observation(
        '{"id":"owner-resource-1","ownerId":"owner","visibility":"shared","value":"team-doc"}'
      ),
      secondIdentityOwnRead: observation(
        '{"id":"member-resource-1","ownerId":"member","visibility":"shared","value":"own"}'
      ),
      secondIdentityOwnerRead: observation(
        '{"id":"owner-resource-1","ownerId":"owner","visibility":"shared","value":"team-doc"}'
      ),
      identitiesAuthorized: true
    })
    expect(shared.verdict).toBe('not-confirmed')
    expect(shared.failedChecks).toContain('not-public-or-shared-visibility')

    const session = assessIdor({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead: observation('{"error":"unauthorized"}', 401),
      secondIdentityOwnRead: observation('{"error":"unauthorized"}', 401),
      secondIdentityOwnerRead: observation('{"error":"unauthorized"}', 401),
      identitiesAuthorized: true
    })
    expect(session.verdict).toBe('inconclusive')

    const dynamic = assessIdor({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead: observation(
        '{"id":"owner-resource-1","ownerId":"owner","value":"aaaaaaaa"}'
      ),
      secondIdentityOwnRead: observation(
        '{"id":"member-resource-1","ownerId":"member","value":"own"}'
      ),
      secondIdentityOwnerRead: observation(
        '{"id":"owner-resource-1","ownerId":"owner","value":"bbbbbbbb"}'
      ),
      identitiesAuthorized: true
    })
    expect(dynamic.verdict).toBe('inconclusive')
  })

  it('treats CSP and dynamic-nonce XSS blocks as inconclusive, not not-confirmed', () => {
    const marker = 'agx_0011223344556677'
    const browser: BrowserObservation = {
      result: {
        requestId: 'browser-csp',
        status: 'succeeded',
        finalUrl: 'https://lab.test/',
        links: [],
        forms: [],
        markerExecuted: false,
        networkRequestsBlocked: 0,
        resultBytes: 0,
        durationMs: 20
      },
      evidenceRefs: ['browser-summary', 'dom-snapshot'],
      toolCallId: 'tool-browser-csp',
      proposalId: 'proposal-browser-csp',
      policyDecisionId: 'decision-browser-csp'
    }
    const cspHttp: HttpObservation = {
      ...observation(`<p>${marker}</p>`),
      result: {
        ...observation(`<p>${marker}</p>`).result,
        responseHeaders: {
          'content-type': 'text/html',
          'content-security-policy': "default-src 'none'"
        }
      }
    }
    expect(assessXss({ marker, http: cspHttp, browser }).verdict).toBe('inconclusive')

    const nonceHttp = observation(
      `<body data-nonce="n-1">Search: ${marker}</body>`
    )
    expect(assessXss({ marker, http: nonceHttp, browser }).verdict).toBe(
      'inconclusive'
    )
  })
})
