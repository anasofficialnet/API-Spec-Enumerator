# AASE

AASE is a local-first API security scanner built with Next.js and FastAPI. It ingests captured HTTP traffic, normalizes it into endpoint inventory, generates scan cases from real request shapes, and executes those cases against an allowlisted target.

The project is designed for authorized API testing, internal verification, and repeatable local analysis. The current codebase includes live request execution, source-aware endpoint discovery, scan preview, cancellation, reporting, and several focused API security modules.

## What AASE does today

### Traffic ingestion and normalization

AASE ingests:

- HAR files
- Burp Suite XML
- mitmproxy JSON
- JSONL or NDJSON traffic
- raw pasted HTTP requests

Captured requests are grouped into normalized endpoints such as:

- `GET /users/1` -> `GET /users/{id}`
- `GET /orders/55` -> `GET /orders/{id}`

The backend keeps request structure, inferred parameters, body fields, auth hints, and per-endpoint case counts.

### Source-aware endpoint inventory

Each endpoint row carries discovery metadata so the UI can show where it came from and how trustworthy it is.

Source labels:

| Internal source | UI label | Meaning |
| --- | --- | --- |
| `traffic` | Captured Traffic | Parsed directly from uploaded traffic or raw HTTP paste |
| `spec` | API Documentation | Extracted from Swagger or OpenAPI |
| `crawl` | Frontend Discovery | Extracted from HTML, JavaScript, or source maps |
| `response_link` | Response Discovery | Extracted from URLs and paths inside API responses |
| `seed_probe` | Recon Guess | Seeded recon probe such as `/graphql` or `/openapi.json` |
| `unknown` | Unknown | Fallback when metadata is not available |

When multiple records collapse into the same normalized endpoint, AASE preserves all known sources and promotes the highest-trust source as the primary label.

Trust order:

1. Captured Traffic
2. API Documentation
3. Frontend Discovery
4. Response Discovery
5. Recon Guess
6. Unknown

Seeded recon endpoints also carry discovery status:

- `guessed`
- `confirmed`
- `failed`
- `derived`

### Deep auto-recon

AASE supports direct target recon through the backend. Current recon combines:

- seeded API and documentation probes
- HTML link extraction
- JavaScript route extraction
- frontend bundle discovery
- source-map discovery through `sourceMappingURL`
- source-map parsing from `sources` and `sourcesContent`
- JSON response path extraction
- OpenAPI and Swagger parsing

This is stronger than simple wordlist probing because it can lift endpoints from frontend bundles and structured API responses, not only from guessed paths.

Important scope note:

- Recon still includes seeded guesses, but those endpoints are labeled as `Recon Guess` in the inventory
- discovered routes from bundles, source maps, responses, and specs are tracked separately

### Scan planning and live execution

AASE has both preview and live execution paths.

Preview mode:

- builds the real scan plan
- returns exact case counts per selected endpoint
- does not execute network requests

Live mode:

- runs asynchronous HTTP requests with `httpx`
- supports rate limiting and concurrency control
- supports retry and exponential backoff for transient errors
- supports scan cancellation through `POST /api/scan/{scan_id}/cancel`
- streams progress through Server-Sent Events

### Scan configuration and guardrails

The scan panel includes:

- Safe, Standard, and Aggressive presets
- context-aware validation for risky modules
- help tooltips for every control
- exact case preview before execution

Examples of built-in guardrails:

- BOLA or IDOR detection requires a second user token
- OAST requires a reachable callback URL
- Auto Login requires login URL, username, and password
- race testing is blocked when only read endpoints are selected
- GraphQL and WebSocket probing is only recommended when matching endpoints exist

### Security modules in the current implementation

AASE currently includes:

- auth checks
- hidden parameter probing
- CORS checks
- verbose error detection
- SQLi, XSS, and SSTI payload families
- BOLA or IDOR detection
- stateful workflow fuzzing
- race-condition testing
- JSON mutation testing
- GraphQL probing
- WebSocket upgrade checks
- attack graph construction
- auto login and session reuse
- OAST callback correlation
- OpenAPI shadow API diffing
- patch suggestion generation

### Developer-grade output

Findings are exported with developer-oriented detail, not only severity summaries.

Each recorded finding can include:

- replay URL
- replay `curl`
- request summary
- response summary
- developer notes
- verification steps
- recommendation
- CWE
- CVSS

Available exports:

- `GET /api/scan/{scan_id}/export.json`
- `GET /api/scan/{scan_id}/export.html`

The HTML report is standalone and styled for sharing. The report UI in the frontend also exposes replay and remediation detail.

## Architecture

AASE is split into a React frontend and a FastAPI backend.

Frontend:

- Next.js 15
- React 19
- dashboard for ingestion, endpoint selection, scan configuration, findings, shadow API review, and attack graph inspection

Backend:

- FastAPI control API
- ingestion and parsing pipeline
- endpoint normalization and case planning
- async scan runner
- SSE status stream
- reporting and export routes

Core backend routes:

- `POST /api/ingest`
- `POST /api/ingest/paste`
- `POST /api/recon`
- `POST /api/scan/{scan_id}/preview`
- `POST /api/scan/{scan_id}/run`
- `POST /api/scan/{scan_id}/cancel`
- `GET /api/scan/{scan_id}/status`
- `GET /api/scan/{scan_id}/events`
- `GET /api/scan/{scan_id}/attack-graph`
- `POST /api/scan/{scan_id}/openapi`
- `GET /api/scan/{scan_id}/shadow-report`
- `GET /api/scan/{scan_id}/patches`
- `GET /api/scan/{scan_id}/oast`
- `GET /api/scan/{scan_id}/export.json`
- `GET /api/scan/{scan_id}/export.html`

## Honest scope and current limitations

This project is real, but it should be described honestly.

Current limitations:

- Auto Login is HTTP-session based. It supports common JSON and form login patterns, cookie reuse, token capture, and CSRF extraction. It is not a headless browser OAuth or SSO engine.
- OAST support is HTTP callback based and correlated inside the app. It is not a managed external DNS plus HTTP OAST platform.
- WebSocket support currently focuses on upgrade, origin, and auth checks. It is not full message-frame fuzzing.
- Recon combines guessed and discovered endpoints. The source label in the endpoint inventory is the intended trust signal.
- Some finding classes are stronger proof than others. For example, confirmed cross-user access replays and blind callback evidence are stronger than low-severity reflection or behavior-change heuristics.

## Local setup

### Requirements

- Node.js 18 or later
- Python 3.10 or later

### Install

```bash
npm install
pip install -r backend/requirements.txt
```

### Configure frontend to backend

The frontend reads the backend origin from `.env.example`:

```bash
NEXT_PUBLIC_API_BASE=http://127.0.0.1:8010
```

You can use either:

- `NEXT_PUBLIC_API_BASE`
- `NEXT_PUBLIC_BACKEND_URL`

### Run locally

Start both frontend and backend:

```bash
npm run dev
```

Default local ports:

- frontend: `http://127.0.0.1:4028`
- backend: `http://127.0.0.1:8010`

## Safe local verification

AASE includes a safe mock target and an end-to-end verification script so you can validate the full flow without touching third-party systems.

Start the mock API:

```bash
python -m uvicorn backend.mock_target:app --host 127.0.0.1 --port 8055
```

Start the app:

```bash
npm run dev
```

Run the safe E2E flow:

```bash
python backend/e2e_safe_test.py
```

That flow exercises:

- auto-recon
- endpoint ingestion
- attack graph generation
- exact preview counts
- live scan execution
- OAST event recording
- HTML report export
- scan cancellation

## Example files

Included example inputs:

- [examples/sample.har](examples/sample.har)
- [examples/sample.jsonl](examples/sample.jsonl)
- [examples/sample_raw_http.txt](examples/sample_raw_http.txt)
- [example_spec.yaml](example_spec.yaml)

## Testing

Backend tests:

```bash
python -m pytest backend/tests/test_parsers.py backend/tests/test_power_modules.py backend/tests/test_scan_validation.py backend/tests/test_reporting.py -q -p no:cacheprovider
```

Frontend utility tests:

```bash
node --test src/app/dashboard/components/scanConfigUtils.test.mjs src/app/dashboard/components/endpointSource.test.mjs
```

Type check:

```bash
npx tsc --noEmit --incremental false
```

## Safety

- Only test systems you own or are explicitly authorized to assess
- Keep aggressive payloads, race testing, and live OAST callbacks for controlled environments
- Use preview and dry run first when validating new targets
- Use the allowlist and target-base override deliberately

## Repository highlights

- [backend/main.py](backend/main.py)
- [backend/modules/auto_recon.py](backend/modules/auto_recon.py)
- [backend/modules/report_generator.py](backend/modules/report_generator.py)
- [backend/modules/attack_graph.py](backend/modules/attack_graph.py)
- [backend/mock_target.py](backend/mock_target.py)
- [src/app/dashboard/components/DashboardInteractive.tsx](src/app/dashboard/components/DashboardInteractive.tsx)
- [src/app/dashboard/components/FuzzConfig.tsx](src/app/dashboard/components/FuzzConfig.tsx)
- [src/app/reports/components/ReportsInteractive.tsx](src/app/reports/components/ReportsInteractive.tsx)
