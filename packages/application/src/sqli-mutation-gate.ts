export class DestructiveSqliMutationError extends Error {
  readonly code = 'destructive-sqli-mutation'

  constructor(message: string) {
    super(message)
    this.name = 'DestructiveSqliMutationError'
  }
}

const DESTRUCTIVE_SQL_PATTERNS: readonly RegExp[] = [
  /\b(?:drop|truncate|alter)\s+(?:database|schema|table|index|view)\b/i,
  /\bdelete\s+from\b/i,
  /\bupdate\s+[\w.[\]"`]+\s+set\b/i,
  /\binsert\s+into\b/i,
  /\bunion\b[\s\S]*\bselect\b/i,
  /;\s*(?:select|drop|truncate|alter|insert|update|delete|create|grant|exec|execute|waitfor|copy|load)\b/i,
  /\b(?:load_file|into\s+(?:out|dump)file)\b/i,
  /\bcopy\s+[\s\S]*\bfrom\b/i,
  /\b(?:xp_cmdshell|sp_configure|sp_oacreate)\b/i,
  /\b(?:create|grant)\s+(?:user|role|table|database)\b/i
]

export function isDestructiveSqliMutation(value: string): boolean {
  return DESTRUCTIVE_SQL_PATTERNS.some((pattern) => pattern.test(value))
}

export function assertNonDestructiveSqliMutation(value: string): void {
  if (isDestructiveSqliMutation(value)) {
    throw new DestructiveSqliMutationError(
      'SQLi mutation is destructive, stacked, extracting, or executes a write.'
    )
  }
}
