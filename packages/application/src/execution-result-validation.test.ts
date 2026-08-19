import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  RunnerOutputValidationError,
  validateBrowserRunnerOutput,
  validateHttpRunnerOutput
} from './execution-result-validation'

class ForgedByteLength extends Uint8Array {
  override get byteLength(): number {
    return 1
  }
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

describe('runner output byte snapshots', () => {
  it('rejects a Uint8Array subclass that understates an HTTP body', () => {
    const responseBody = new ForgedByteLength(64)
    const value = {
      requestId: 'http-byte-forgery',
      status: 'succeeded',
      finalUrl: 'https://fixture.example.test/data',
      method: 'GET',
      statusCode: 200,
      requestHeaders: [],
      responseHeaders: {
        'content-type': 'application/octet-stream'
      },
      responseBody,
      responseBodySha256: sha256(responseBody),
      responseBytes: 1,
      durationMs: 1,
      resolvedAddresses: ['203.0.113.10']
    }
    Object.defineProperty(value, 'claimToken', {
      value: Object.freeze(Object.create(null)),
      enumerable: false,
      configurable: false,
      writable: false
    })

    expect(() =>
      validateHttpRunnerOutput(value, {
        requestId: value.requestId,
        wire: {
          method: 'GET',
          url: value.finalUrl,
          headers: []
        },
        timeoutMs: 1_000,
        maxResponseBytes: 1
      })
    ).toThrow(RunnerOutputValidationError)
  })

  it('rejects a Uint8Array subclass that understates a browser screenshot', () => {
    const screenshot = new ForgedByteLength(64)
    const domSnapshot = '<main>fixture</main>'
    const metadataBytes = Buffer.byteLength(
      JSON.stringify({
        title: 'Fixture',
        links: [],
        forms: [],
        markerExecuted: true
      }),
      'utf8'
    )
    const value = {
      requestId: 'browser-byte-forgery',
      status: 'succeeded',
      finalUrl: 'https://fixture.example.test/offline',
      pageTitle: 'Fixture',
      links: [],
      forms: [],
      domSnapshot,
      markerExecuted: true,
      screenshot,
      networkRequestsBlocked: 0,
      resultBytes:
        metadataBytes +
        Buffer.byteLength(domSnapshot, 'utf8') +
        1,
      durationMs: 1
    }

    expect(() =>
      validateBrowserRunnerOutput(value, {
        request: {
          requestId: value.requestId,
          baseUrl: value.finalUrl,
          action: 'verify-xss',
          marker: 'marker',
          timeoutMs: 1_000
        },
        maxResultBytes: value.resultBytes
      })
    ).toThrow(RunnerOutputValidationError)
  })
})
