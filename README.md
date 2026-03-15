<div align="center">
  <h1><b>AASE - Adaptive API Spec Enumerator</b></h1>
  <p><i>A powerful, local-first API traffic analysis and fuzzing tool.</i></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![React](https://img.shields.io/badge/React-19-blue.svg)](https://react.dev)
  [![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org)
  [![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
</div>

<div align="center">
  <b>🟢 Live App: <a href="https://api-spec-enumerator.vercel.app">api-spec-enumerator.vercel.app</a></b>
</div>

<hr/>

## ✨ What is AASE?

**AASE (Adaptive API Spec Enumerator)** is a local-first API security tool designed to analyze captured traffic, normalize API inventory, generate targeted fuzzing cases, and execute those cases against an allowlisted target.

It takes captured HTTP traffic from browsers, Burp Suite, or mitmproxy, groups requests into normalized API endpoints, derives scan cases from real request structure, and runs live checks through a FastAPI backend.

The project consists of two main components:
1. **The Frontend**: A fast `Next.js` and `React 19` interface for ingestion, endpoint review, configuration, findings, and reports.
2. **The Backend**: A `FastAPI` service for parsing, recon, case generation, execution, and reporting.

---

## 🚀 Key Features

### 📥 Universal Traffic Ingestion
Upload your captured API traffic with drag-and-drop ease. Supported formats:
- **HAR (`.har`)**: Best format, exported straight from browser DevTools.
- **Burp Suite XML (`.xml`)**: Export your Burp history directly.
- **mitmproxy JSON (`.json`)**: Raw mitmproxy dumps.
- **JSON Lines (`.jsonl`, `.ndjson`)**: One request record per line.
- **Raw HTTP Paste**: Paste raw HTTP requests straight into the dashboard.

### 🧠 Smart Endpoint Discovery & Normalization
AASE parses hundreds of requests and normalizes dynamic segments into stable endpoint shapes.

For example:
- `GET /api/users/1` and `GET /api/users/42` automatically become `GET /api/users/{id}`.

The dashboard shows backend-derived case counts for each endpoint, and preview mode refreshes those counts from the live scan plan for the current configuration.

### 🏷️ Source-Aware Endpoint Inventory
Each endpoint now carries source metadata so you can see where it came from and how trustworthy it is.

Current source labels:
- **Captured Traffic**
- **API Documentation**
- **Frontend Discovery**
- **Response Discovery**
- **Recon Guess**

When multiple observed paths normalize into one endpoint shape, AASE preserves all known sources and promotes the highest-trust source as the main label shown in the inventory.

### 🕸️ Deep Auto-Recon
AASE can build scan state directly from a target URL through the backend recon engine.

Current recon combines:
- seeded API and documentation probes
- HTML link extraction
- JavaScript route extraction
- frontend bundle discovery
- source-map discovery via `sourceMappingURL`
- source-map parsing from `sources` and `sourcesContent`
- JSON response path extraction
- OpenAPI and Swagger parsing

Recon guesses are tracked separately from confirmed or derived endpoints, so the UI makes the difference visible instead of mixing them together.

### 🛡️ Safe & Aggressive Probe Generation
- **Safe Mode**: Checks for baseline responses, missing CORS protections, hidden parameters, and simple authentication bypasses.
- **Aggressive Mode**: Mutates body payloads and query strings looking for edge-case vulnerabilities like **SQLi, XSS, and SSTI**.
- **Dry Run**: Validates targets, parsed parameters, and generated test queries without sending real traffic.

### ⚡ Live Scan Controls
AASE includes several operator-friendly controls for real scan execution:
- **Exact Preview Counts**: Build the real scan plan before launch.
- **Retries + Backoff**: Retry timeouts, rate limits, and transient server errors.
- **Cancellation**: Stop long-running scans without restarting the app.
- **SSE Progress Streaming**: Watch live scan progress and findings in real time.
- **Target Allowlisting**: Restrict execution to an approved target host.

### 🧪 Power Modules
AASE currently includes focused security modules for:
- **BOLA / IDOR Detection**
- **Stateful Fuzzing**
- **Race Condition Testing**
- **JSON Mutations**
- **GraphQL Probing**
- **WebSocket Upgrade Checks**
- **Attack Graph Generation**
- **Auto Login and Session Reuse**
- **Shadow API Diffing**
- **OAST Callback Tracking**

### 📊 Operator-Friendly Reporting & Exporting
Get real-time feedback during live scans via Server-Sent Events (SSE). Once a scan completes, you can review everything in the **Findings** tab and export the results:
- **Export JSON**: Downloads a machine-readable report with findings, request and response evidence, and metadata.
- **Export HTML**: Generates a standalone executive report with severity, CVSS, CWE, remediation guidance, and replay detail.

The reporting pipeline now includes developer-grade output such as:
- replay-ready request URLs
- `curl` reproduction commands
- request and response summaries
- verification steps
- developer notes alongside remediation guidance

### ⚙️ Advanced Fuzzing Configuration
For advanced operators, AASE supports a tunable fuzzing engine via its backend configuration architecture:
- **Payload Dictionaries**: SQLi, XSS, and SSTI payload families during Aggressive Mode.
- **Target Overrides**: Rewrite the base URL during test execution without altering ingested capture files.
- **Presets**: Safe, Standard, and Aggressive presets for faster campaign setup.
- **Validation Guards**: Warn or block risky features when required inputs are missing.

---

## 🛠️ How It Works (Architecture)

> [!IMPORTANT]
> **Cloud Deployment (Free Tier Sleep Warning)**
> The live deployment of this application runs its frontend on Vercel and its backend on Render's free tier.
> Render free instances automatically spin down after inactivity.
>
> If you visit the site and try to upload a file for the first time in a while, it may take **45 to 60 seconds** for the backend to wake up.

- **Frontend Environment**: Next.js 15, hosted on Vercel Edge.
- **Backend API**: Python FastAPI, hosted as a Python 3 web service on Render.

The current local architecture is split into these layers:
- **Ingestion Layer**: HAR, Burp XML, mitmproxy JSON, JSONL, and raw HTTP parsing
- **Discovery Layer**: endpoint normalization, source labeling, recon, and spec parsing
- **Planning Layer**: case generation, preview counts, and endpoint selection
- **Execution Layer**: async HTTP execution, retries, cancellation, and streaming status
- **Analysis Layer**: finding detection, attack graph generation, shadow API diffing, and patch suggestion generation
- **Reporting Layer**: JSON export, HTML executive reports, replay commands, and remediation notes

---

## 💻 How Can You Use It?

### Prerequisites

You need the following installed:
- Node.js (v18+) and npm
- Python (v3.10+) and pip

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/anasofficialnet/API-Spec-Enumerator.git
   cd API-Spec-Enumerator
   ```

2. **Install Frontend Dependencies:**
   ```bash
   npm install
   ```

3. **Install Backend Dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   cd ..
   ```

### Running the App Locally

To start the local command center, run:

```bash
npm run dev
```

This uses `concurrently` to bring up:
- FastAPI backend on port `8010`
- Next.js frontend on port `4028`

Open your browser to: **[http://localhost:4028](http://localhost:4028)**

If you want to point the frontend at a specific backend origin, use:

```bash
NEXT_PUBLIC_API_BASE=http://127.0.0.1:8010
```

---

## 🧪 Testing an Example

Want to see it in action without touching a live target?

1. Once the app is running, navigate to the Dashboard.
2. Drag and drop the provided example file located at `examples/sample.har`.
3. AASE will immediately parse out the simulated architecture:
   - `GET /api/users`
   - `GET /api/users/{id}`
   - `POST /api/users`
   - `POST /api/auth/login`
4. Set **Dry Run Mode** to `On` and hit **Start New Scan**.
5. Review the generated endpoint inventory and scan plan in the dashboard.

### Safe Local Verification

AASE also includes a safe mock target and a full local verification flow.

1. Start the mock API target:
   ```bash
   python -m uvicorn backend.mock_target:app --host 127.0.0.1 --port 8055
   ```
2. Start AASE:
   ```bash
   npm run dev
   ```
3. Run the safe end-to-end verification:
   ```bash
   python backend/e2e_safe_test.py
   ```

This flow exercises:
- auto-recon
- attack graph generation
- exact preview counts
- live scan execution
- OAST event recording
- HTML report export
- scan cancellation

Reusable sample fixtures live under:
- `examples/`
- `examples/e2e/`

Generated local E2E outputs are written under:
- `artifacts/e2e/`

---

## 🔒 Security & Safety Notes

- **Never fuzz applications without authorization.** This tool is intended for local development, research, and authorized penetration testing on systems you explicitly control.
- AASE respects standard `robots.txt` paths by default during live scans.
- No remote telemetry or analytics are built into AASE. Scan logic, parameters, and results stay local to the running process.
- Prefer **Preview** or **Dry Run** first when validating a new target or a new scan profile.
- Keep aggressive payloads, race testing, and live OAST callbacks for controlled or explicitly approved environments.

---

<br/>
<div align="center">
  <b>Built with ❤️ by Anas, focusing on the future of clean, automated AppSec.</b><br/>
  <a href="https://github.com/anasofficialnet/API-Spec-Enumerator/issues">Report an issue</a> • <a href="https://github.com/anasofficialnet/API-Spec-Enumerator/pulls">Submit a pull request</a>
</div>
