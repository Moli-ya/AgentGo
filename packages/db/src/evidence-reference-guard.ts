import type { DatabaseSync } from 'node:sqlite'

const EVIDENCE_REFERENCE_QUERY = `
WITH candidate(id) AS (VALUES (?))
SELECT 1 AS referenced
WHERE
  EXISTS (
    SELECT 1 FROM execution_lease_evidence
    WHERE evidence_id = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM finding_evidence
    WHERE evidence_id = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM evidence_items
    WHERE derived_from = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM interactions
    WHERE request_ref = (SELECT id FROM candidate)
       OR response_ref = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM inventory_sources
    WHERE evidence_ref = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM tool_calls
    WHERE output_ref = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM validation_runs
    WHERE baseline_ref = (SELECT id FROM candidate)
       OR test_ref = (SELECT id FROM candidate)
       OR negative_control_ref = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1 FROM reports
    WHERE content_ref = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1
    FROM signals, json_each(signals.evidence_refs) AS evidence_ref
    WHERE evidence_ref.type = 'text'
      AND evidence_ref.value = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1
    FROM agent_runs, json_each(agent_runs.input_refs) AS input_ref
    WHERE input_ref.type = 'text'
      AND input_ref.value = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1
    FROM agent_runs, json_each(agent_runs.output_refs) AS output_ref
    WHERE output_ref.type = 'text'
      AND output_ref.value = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1
    FROM execution_leases,
         json_each(execution_leases.evidence_refs_json) AS lease_ref
    WHERE lease_ref.type = 'text'
      AND lease_ref.value = (SELECT id FROM candidate)
  )
  OR EXISTS (
    SELECT 1
    FROM confirmation_rules,
         json_each(confirmation_rules.source_refs) AS source_ref
    WHERE source_ref.type = 'text'
      AND source_ref.value = (SELECT id FROM candidate)
  )
LIMIT 1
`

/**
 * Call while holding the transaction that may delete the Evidence row.
 * Malformed legacy JSON propagates as an error so cleanup fails closed.
 */
export function isEvidenceItemReferenced(
  database: DatabaseSync,
  evidenceId: string
): boolean {
  return Boolean(
    database.prepare(EVIDENCE_REFERENCE_QUERY).get(evidenceId)
  )
}
