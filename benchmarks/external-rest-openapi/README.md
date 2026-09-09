# Swagger Petstore V3 external REST/OpenAPI holdout

This directory reserves a real third-party target for the Day20 compatibility
gate. It is separate from the project-authored `agentgo-local-holdout` and is
the only one of the two that may use `resultClass=external-local-holdout`.

Pinned target:

- upstream: `swagger-api/swagger-petstore`;
- release: `swagger-petstore-v3-1.0.16`;
- license: Apache-2.0;
- image: `swaggerapi/petstore3@sha256:221da3038bf91fad98e249d5f123cbca21d5bfc8e10a786c8c060ec8058cc522`;
- local OpenAPI document: `http://127.0.0.1:18080/api/v3/openapi.json`.

The fixed image was downloaded and run through the Docker Desktop Linux engine
inside WSL on 2026-09-07. The setup command is:

```powershell
wsl.exe docker pull swaggerapi/petstore3@sha256:221da3038bf91fad98e249d5f123cbca21d5bfc8e10a786c8c060ec8058cc522
wsl.exe docker run --rm --name agentgo-petstore3-holdout -p 127.0.0.1:18080:8080 swaggerapi/petstore3@sha256:221da3038bf91fad98e249d5f123cbca21d5bfc8e10a786c8c060ec8058cc522
```

In another shell, verify the fixed target without giving it a benchmark score:

```powershell
pnpm tsx packages/evaluation/src/run-external-openapi-preflight.ts --base-url http://127.0.0.1:18080
```

The preflight rejects non-loopback URLs, redirects, oversized documents,
unexpected OpenAPI versions, unexpected product versions and missing Petstore
routes. Passing it means only that the pinned external target is locally ready.
The Day20 compatibility replay completed with two reviewed GET variants and a
separate ignored artifact under `benchmark-results/day20-external-petstore-*`.
The artifact records import/preview hashes, Policy/Grant/Lease IDs and response
hashes. It is a compatibility result only and does not claim vulnerability
accuracy. The container is bound to loopback and must be removed after review:

```powershell
wsl.exe docker rm -f agentgo-petstore3-holdout
```
