import type { DefinitionRegistry } from '@agentgo/domain'
import { isLegacyV1VulnerabilityFamily } from '@agentgo/contracts'
import {
  V1_CONFIRMATION_RULES,
  type ConfirmationRuleDefinition,
  type ValidationAssessment
} from './validation-engine'

export interface FindingAssembly {
  readonly title: string
  readonly displayName: string
  readonly severity: ValidationAssessment['severity']
  readonly cwe: string
  readonly owasp: string
  readonly remediation: string[]
  readonly confirmationRuleId: string
  readonly confirmationRuleVersion: string
}

export class FindingAssembler {
  constructor(private readonly registry: DefinitionRegistry) {}

  displayName(familyId: string): string {
    return this.registry.getFamily(familyId)?.displayName ?? familyId
  }

  familyDisplayNames(): Record<string, string> {
    const names: Record<string, string> = {}
    for (const bundle of this.registry.listBundles()) {
      names[bundle.bundle.manifest.family.familyId] =
        bundle.bundle.manifest.family.displayName
    }
    return names
  }

  confirmationRule(familyId: string): ConfirmationRuleDefinition | undefined {
    if (!isLegacyV1VulnerabilityFamily(familyId)) return undefined
    return V1_CONFIRMATION_RULES[familyId]
  }

  assemble(input: {
    readonly familyId: string
    readonly techniqueId: string
    readonly moduleVersion: string
    readonly pathname: string
    readonly parameterName?: string
    readonly assessment: ValidationAssessment
  }): FindingAssembly {
    const displayName = this.displayName(input.familyId)
    const bundle = this.registry.listBundles().find(
      (item) =>
        item.bundle.manifest.family.familyId === input.familyId &&
        item.bundle.manifest.moduleVersion === input.moduleVersion
    )
    const remediation = bundle?.bundle.remediations.find((item) =>
      item.applicableTechniqueIds.includes(input.techniqueId)
    )?.remediation
    const remediationItems = remediation
      ? remediation.split('；').map((item) => item.trim()).filter(Boolean)
      : input.assessment.remediation
    const location = input.parameterName
      ? `${input.pathname} 参数 ${input.parameterName}`
      : input.pathname
    return {
      title: `${displayName}：${location}`,
      displayName,
      severity: input.assessment.severity,
      cwe: input.assessment.cwe,
      owasp: input.assessment.owasp,
      remediation: remediationItems,
      confirmationRuleId: input.assessment.confirmationRuleId,
      confirmationRuleVersion: input.assessment.confirmationRuleVersion
    }
  }
}
