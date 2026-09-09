# AgentGo sealed local holdout pack

This pack is a **version-pinned, loopback-only, resettable** evaluation target.

- Pack ID: `agentgo-local-holdout`
- Pack version: `agentgo-local-holdout/1.0.0`
- Bind address: `127.0.0.1` ephemeral port
- Reset: `GET /holdout/v1/reset` (fixture namespace only)
- Outbound: same-origin loopback callback only
- License: `project-internal-test-data` (see `LICENSE`)
- Coverage class: `self-built-fixture` (the historical suite ID does not establish external provenance)

It is **not** a copy of `/cases/` or `/research/` on the Day15/16 development fixture. It is also **not** a third-party product (Juice Shop, DVWA, or similar). Scores from this pack must not be used to claim real-world or third-party product accuracy.

Ground truth was written before the holdout server was implemented. Scanner confirmation rules must stay frozen after scores are observed. If a rule change is required, cut a new pack version and mark the old run as development feedback.
