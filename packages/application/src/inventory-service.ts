import {
  RedactedInventoryPreviewSchema,
  RequestVariantRecordSchema,
  RetireVariantInputSchema,
  ReviewVariantInputSchema,
  UpsertInventoryInputSchema,
  UpsertInventoryResultSchema,
  type InventoryExecutionClass,
  type RequestVariantRecord,
  type RetireVariantInput,
  type ReviewVariantInput,
  type UpsertInventoryInput,
  type UpsertInventoryResult
} from '@agentgo/contracts'
import {
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRefs,
  redactInventoryPreview,
  redactInventoryText,
  redactInventoryUrlPreview,
  stableInventoryHash
} from '@agentgo/domain'
import {
  AgentGoRepository,
  type PreparedInventoryWrite
} from '@agentgo/db'
import type { ProbeCapabilityCatalog } from '@agentgo/security-policy'

const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const WRITE_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH'])
const FORBIDDEN_HTTP_METHODS = new Set(['CONNECT', 'DELETE', 'TRACE'])
const HTTP_READ_CAPABILITIES = new Set([
  'http.reviewed-read',
  'http.identity-read-compare'
])
const HTTP_TEST_OBJECT_WRITE_CAPABILITY = 'http.test-object-write'

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function canonicalContentType(value: string | undefined): string | undefined {
  if (!value) return undefined
  const mediaType = value.split(';', 1)[0]?.trim().toLowerCase()
  if (!mediaType || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(mediaType)) {
    throw new TypeError(`Invalid inventory content type: ${value}`)
  }
  return mediaType
}

function sanitizeInitiator(value: string | undefined): string | undefined {
  if (!value) return undefined
  try {
    return redactInventoryText(redactInventoryUrlPreview(value), 2_048)
  } catch {
    return redactInventoryText(value, 2_048)
  }
}

/**
 * Computes risk independently from human review. This classification is not an
 * execution grant; later execution must also require review, policy, and the
 * appropriate compiler/adapter.
 */
export function classifyInventoryExecution(
  input: Pick<
    UpsertInventoryInput,
    'method' | 'codec' | 'transport' | 'requiredCapabilityIds'
  >,
  capabilityCatalog: ProbeCapabilityCatalog
): InventoryExecutionClass {
  if (FORBIDDEN_HTTP_METHODS.has(input.method)) return 'forbidden'
  if (input.requiredCapabilityIds.length === 0) return 'inventory-only'
  if (input.transport !== 'standard-http' || input.codec !== 'none') {
    return 'unsupported'
  }

  const descriptors = input.requiredCapabilityIds.map((id) =>
    capabilityCatalog.get(id)
  )
  if (descriptors.some((descriptor) => descriptor === undefined)) {
    return 'unsupported'
  }

  if (SAFE_HTTP_METHODS.has(input.method)) {
    if (
      !input.requiredCapabilityIds.some((id) => HTTP_READ_CAPABILITIES.has(id))
    ) {
      return 'inventory-only'
    }
    return descriptors.some((descriptor) => descriptor?.riskFloor === 'l2')
      ? 'active-l2'
      : 'active-l1'
  }

  if (WRITE_HTTP_METHODS.has(input.method)) {
    return input.requiredCapabilityIds.includes(
      HTTP_TEST_OBJECT_WRITE_CAPABILITY
    )
      ? 'active-l2'
      : 'unsupported'
  }
  return 'unsupported'
}

export class InventoryService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly capabilityCatalog: ProbeCapabilityCatalog
  ) {}

  async upsertInventory(input: unknown): Promise<UpsertInventoryResult> {
    const parsed = UpsertInventoryInputSchema.parse(input)
    const canonicalRoute = canonicalizeInventoryUrl(parsed.url)
    const bodyShape = canonicalizeInventoryBodyShape(parsed.bodyShape)
    const allowedHeaders = canonicalizeAllowedHeaderDescriptors(
      parsed.allowedHeaders
    )
    const selectors = canonicalizeSelectorRefs(parsed.selectors)
    const requiredCapabilityIds = [...parsed.requiredCapabilityIds].sort(compareText)
    const contentType = canonicalContentType(parsed.contentType)
    const redactedPreview = RedactedInventoryPreviewSchema.parse(
      redactInventoryPreview(parsed.preview)
    )
    const structuralValue = {
      contentType: contentType ?? null,
      bodyShape,
      codec: parsed.codec,
      transport: parsed.transport,
      allowedHeaders,
      templateVersion: parsed.templateVersion,
      requiredCapabilityIds,
      selectors
    }
    const structureHash = stableInventoryHash(structuralValue)
    const pageId = parsed.pageId ?? parsed.source.pageId
    const initiator = sanitizeInitiator(parsed.source.initiator)
    const provenanceHash = stableInventoryHash({
      scanId: parsed.scanId,
      method: parsed.method,
      canonicalRoute,
      structureHash,
      type: parsed.source.type,
      sourceHash: parsed.source.sourceHash,
      pageId: pageId ?? null,
      evidenceRef: parsed.source.evidenceRef ?? null,
      initiator: initiator ?? null
    })
    const prepared: PreparedInventoryWrite = {
      scanId: parsed.scanId,
      ...(pageId ? { pageId } : {}),
      method: parsed.method,
      canonicalRoute,
      compatibilityUrl: redactedPreview.url,
      ...(contentType ? { contentType } : {}),
      bodyShape,
      codec: parsed.codec,
      transport: parsed.transport,
      allowedHeaders,
      templateVersion: parsed.templateVersion,
      requiredCapabilityIds,
      redactedPreview,
      executionClass: classifyInventoryExecution(
        {
          method: parsed.method,
          codec: parsed.codec,
          transport: parsed.transport,
          requiredCapabilityIds
        },
        this.capabilityCatalog
      ),
      structureHash,
      selectors: selectors.map((selector) => ({
        selector,
        structureHash: stableInventoryHash(selector)
      })),
      source: {
        type: parsed.source.type,
        sourceHash: parsed.source.sourceHash,
        provenanceHash,
        ...(pageId ? { pageId } : {}),
        ...(parsed.source.evidenceRef
          ? { evidenceRef: parsed.source.evidenceRef }
          : {}),
        ...(initiator ? { initiator } : {}),
        confidencePpm: Math.round(parsed.source.confidence * 1_000_000)
      }
    }
    return UpsertInventoryResultSchema.parse(
      await this.repository.persistInventory(prepared)
    )
  }

  async reviewVariant(input: unknown): Promise<RequestVariantRecord> {
    const parsed: ReviewVariantInput = ReviewVariantInputSchema.parse(input)
    return RequestVariantRecordSchema.parse(
      await this.repository.reviewInventoryVariant(parsed)
    )
  }

  async retireVariant(input: unknown): Promise<RequestVariantRecord> {
    const parsed: RetireVariantInput = RetireVariantInputSchema.parse(input)
    return RequestVariantRecordSchema.parse(
      await this.repository.retireInventoryVariant(parsed)
    )
  }
}
