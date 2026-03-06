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

**AASE (Adaptive API Spec Enumerator)** is a fast, offline-capable security tool designed to analyze API traffic and automatically discover attack surfaces. 

It takes captured HTTP traffic (from browsers, Burp Suite, or mitmproxy) as input, groups requests into normalized API endpoints, automatically crafts fuzzing test cases, and runs them against the target.

The project consists of two powerful components:
1. **The Frontend**: A blazingly fast `Next.js` and `React 19` interface.
2. **The Backend**: A `FastAPI` server for rapid parsing, payload generation, and execution.

---

## 🚀 Key Features

### 📥 Universal Traffic Ingestion
Upload your captured API traffic with drag-and-drop ease. Supported formats:
- **HAR (`.har`)**: Best format, exported straight from browser DevTools.
- **Burp Suite XML (`.xml`)**: Export your Burp history directly.
- **mitmproxy JSON (`.json`)**: Raw mitmproxy dumps.
- **JSON Lines (`.jsonl`, `.ndjson`)**: One request record per line.
- **Raw HTTP Paste**: Paste raw HTTP requests straight into the dashboard.

### 🧠 Smart Endpoint Discovery
AASE intelligently parses hundreds of requests and normalizes dynamic segments. 
For example:
- `GET /api/users/1` and `GET /api/users/42` automatically become `GET /api/users/{id}`.
It automatically calculates exactly how many potential fuzzing vectors are present on every discovered endpoint.

### 🛡️ Safe & Aggressive Probe Generation
- **Safe Mode**: Checks for basic baseline responses, missing CORS headers, hidden parameters, and simple authentication bypasses.
- **Aggressive Mode**: Intelligently mutates body payloads and query strings looking for edge-case vulnerabilities like **SQLi, XSS, and SSTI**.
- **Dry Run**: Validate your targets, parsed parameters, and generated test queries without sending a single byte of real traffic.

### 📊 Operator-Friendly Reporting
Get real-time feedback during live scans via Server-Sent Events (SSE). Once complete, you have an elegant "Findings" tab, from which you can export findings as:
- A raw **JSON** report for further scripting.
- A beautiful single-file **HTML** report to send off to your security team.

---

## 🛠️ How It Works (Architecture)

> [!IMPORTANT]
> **Cloud Deployment (Free Tier Sleep Warning)**
> The live deployment of this application runs its frontend on Vercel and its backend on Render's free tier. 
> Render's free servers **automatically spin down and go to sleep** after 15 minutes of inactivity. 
> 
> If you visit the site and try to upload a file for the first time in a while, it may take **45 to 60 seconds** for the backend to wake up. Please be patient on the first upload! Every subsequent request will be lightning fast.

- **Frontend Environment**: Next.js 15, hosted on Vercel Edge.
- **Backend API**: Python FastAPI, hosted as a Python 3 Web Service on Render.

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

To start the local command center, you can run a single command that orchestrates both frontend and backend:

```bash
npm run dev
```

*(This uses `concurrently` to bring up the FastAPI backend on port 8010, and Next.js on port 4028.)*

Open your browser to: **[http://localhost:4028](http://localhost:4028)**

---

## 🧪 Testing an Example

Want to see it in action without a target? We got you.

1. Once the app is running, navigate to the Dashboard.
2. Drag and drop the provided example file located at `examples/sample.har`.
3. AASE will immediately parse out the simulated architecture:
   - `GET /api/users`
   - `GET /api/users/{id}`
   - `POST /api/users`
   - `POST /api/auth/login`
4. Set **Dry Run Mode** to `On` and hit "Start New Scan".
5. Watch the 3D dashboard adapt while generating the security probe cases!

---

## 🔒 Security & Safety Notes

- **Never fuzz applications without authorization!** This tool is strictly intended for local development, research, and authorized penetration testing on systems you explicitly control!
- AASE strictly respects standard `robots.txt` paths by default during live scans to prevent unexpected crawling.
- No remote telemetry or analytics exist in AASE. All scan logic, parameters, and results reside locally within memory. Backend state drops completely upon restarting the process.

---

<br/>
<div align="center">
  <b>Built with ❤️ by Anas, focusing on the future of clean, automated AppSec.</b><br/>
  <a href="https://github.com/anasofficialnet/API-Spec-Enumerator/issues">Report an issue</a> • <a href="https://github.com/anasofficialnet/API-Spec-Enumerator/pulls">Submit a pull request</a>
</div>
