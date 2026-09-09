import { describe, expect, it } from 'vitest'
import {
  assertNonDestructiveSqliMutation,
  DestructiveSqliMutationError,
  isDestructiveSqliMutation
} from './sqli-mutation-gate'

const ALLOWED = [
  '1 AND 1=1',
  '1 AND 1=2',
  "agentgo' AND '1'='1",
  "1'",
  '1 AND SLEEP(2)',
  "1 AND pg_sleep(2)",
  "1 WAITFOR DELAY '0:0:2'"
]

const FORBIDDEN = [
  '1; DROP TABLE users',
  '1 UNION SELECT password FROM users',
  "1' UNION ALL SELECT NULL,NULL--",
  '1; INSERT INTO users VALUES (1)',
  '1; UPDATE users SET role=admin',
  '1; DELETE FROM accounts',
  "1' AND LOAD_FILE('/etc/passwd')--",
  "1' INTO OUTFILE '/tmp/x'--",
  "1; COPY users FROM '/tmp/x'",
  "1; EXEC xp_cmdshell 'whoami'",
  'TRUNCATE TABLE sessions',
  'ALTER TABLE users DROP COLUMN email'
]

describe('SQLi destructive mutation gate', () => {
  it('allows non-writing boolean, error, and bounded-time mutations', () => {
    for (const value of ALLOWED) {
      expect(isDestructiveSqliMutation(value), value).toBe(false)
      expect(() => assertNonDestructiveSqliMutation(value)).not.toThrow()
    }
  })

  it('rejects stacked, UNION extraction, file, command, and write statements without I/O', () => {
    for (const value of FORBIDDEN) {
      expect(isDestructiveSqliMutation(value), value).toBe(true)
      expect(() => assertNonDestructiveSqliMutation(value)).toThrow(
        DestructiveSqliMutationError
      )
    }
  })
})
