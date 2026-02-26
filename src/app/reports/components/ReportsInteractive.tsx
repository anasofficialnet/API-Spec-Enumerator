"use client";

import { useState } from "react";
import Icon from "@/components/ui/AppIcon";
import Link from "next/link";

interface ReportFinding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  type: string;
  endpoint: string;
  method: string;
  host: string;
  cvss: number;
  evidence: string;
  request: string;
  response: string;
  recommendation: string;
  cwe: string;
  timestamp: string;
}

const ALL_FINDINGS: ReportFinding[] = [
  {
    id: "F-001",
    severity: "CRITICAL",
    type: "SQL Injection",
    endpoint: "/api/users",
    method: "GET",
    host: "api.targetapp.dev",
    cvss: 9.8,
    evidence: "Parameter 'id' with payload \" OR 1=1-- returned 847 user records (expected 1)",
    request: "GET /api/users?id=1' OR 1=1-- HTTP/1.1\nHost: api.targetapp.dev\nAuthorization: Bearer eyJ...",
    response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"users\":[{\"id\":1,\"email\":\"admin@targetapp.dev\",\"role\":\"admin\"},{\"id\":2,\"email\":\"user@targetapp.dev\",\"role\":\"user\"},...847 more]}",
    recommendation: "Use parameterized queries or prepared statements. Never interpolate user input into SQL strings. Apply input validation and allowlisting.",
    cwe: "CWE-89",
    timestamp: "2026-02-26 05:51:14",
  },
  {
    id: "F-002",
    severity: "HIGH",
    type: "BOLA / IDOR",
    endpoint: "/api/orders/{id}",
    method: "GET",
    host: "api.targetapp.dev",
    cvss: 8.1,
    evidence: "Authenticated as User A (id:42), accessed /api/orders/4821 (owned by User B:77) — received 200 OK with full order data",
    request: "GET /api/orders/4821 HTTP/1.1\nHost: api.targetapp.dev\nAuthorization: Bearer eyJ... (User A token)",
    response: "HTTP/1.1 200 OK\n\n{\"order_id\":4821,\"user_id\":77,\"items\":[...],\"payment\":{\"card_last4\":\"4242\"}}",
    recommendation: "Enforce object-level authorization. Verify the authenticated user owns or has permission to access the requested resource before returning data.",
    cwe: "CWE-639",
    timestamp: "2026-02-26 05:51:18",
  },
  {
    id: "F-003",
    severity: "HIGH",
    type: "Auth Bypass",
    endpoint: "/api/admin/users",
    method: "POST",
    host: "api.targetapp.dev",
    cvss: 7.5,
    evidence: "Removing Authorization header from POST /api/admin/users returned 201 Created — new admin user provisioned without authentication",
    request: "POST /api/admin/users HTTP/1.1\nHost: api.targetapp.dev\n[No Authorization header]\n\n{\"email\":\"attacker@evil.com\",\"role\":\"admin\"}",
    response: "HTTP/1.1 201 Created\n\n{\"id\":1204,\"email\":\"attacker@evil.com\",\"role\":\"admin\",\"created\":\"2026-02-26T05:51:22Z\"}",
    recommendation: "Require valid authentication on all admin endpoints. Apply role-based access control (RBAC). Use middleware-level auth enforcement.",
    cwe: "CWE-306",
    timestamp: "2026-02-26 05:51:22",
  },
  {
    id: "F-004",
    severity: "MEDIUM",
    type: "Missing Rate Limit",
    endpoint: "/api/auth/login",
    method: "POST",
    host: "auth.targetapp.dev",
    cvss: 5.3,
    evidence: "500 consecutive POST requests in 10 seconds with no throttling, lockout, or CAPTCHA challenge observed",
    request: "POST /api/auth/login HTTP/1.1\nHost: auth.targetapp.dev\n\n{\"email\":\"admin@targetapp.dev\",\"password\":\"<brute_force_payload>\"}",
    response: "HTTP/1.1 401 Unauthorized\n\n{\"error\":\"Invalid credentials\"}\n// Repeated 500x with no rate limiting",
    recommendation: "Implement rate limiting (e.g., 5 attempts/minute per IP). Add exponential backoff, account lockout after N failures, and CAPTCHA for repeated failures.",
    cwe: "CWE-307",
    timestamp: "2026-02-26 05:51:29",
  },
  {
    id: "F-005",
    severity: "MEDIUM",
    type: "Mass Assignment",
    endpoint: "/api/users/{id}",
    method: "PUT",
    host: "api.targetapp.dev",
    cvss: 6.5,
    evidence: "PUT /api/users/42 with body {\"role\":\"admin\"} returned 200 OK — user role was elevated without privilege check",
    request: "PUT /api/users/42 HTTP/1.1\nHost: api.targetapp.dev\nAuthorization: Bearer eyJ... (User 42 token)\n\n{\"email\":\"me@test.com\",\"role\":\"admin\"}",
    response: "HTTP/1.1 200 OK\n\n{\"id\":42,\"email\":\"me@test.com\",\"role\":\"admin\"}",
    recommendation: "Use allowlists for updatable fields. Strip sensitive fields (role, permissions, id) from user-controlled input before updating the database.",
    cwe: "CWE-915",
    timestamp: "2026-02-26 05:51:33",
  },
  {
    id: "F-006",
    severity: "LOW",
    type: "Verbose Error",
    endpoint: "/api/internal/debug",
    method: "GET",
    host: "api.targetapp.dev",
    cvss: 3.1,
    evidence: "Endpoint returns full Node.js stack trace including internal file paths and module versions",
    request: "GET /api/internal/debug HTTP/1.1\nHost: api.targetapp.dev",
    response: "HTTP/1.1 200 OK\n\n{\"stack\":\"Error\\n  at /app/node_modules/express/lib/router/index.js:284\",\"env\":\"production\",\"node_version\":\"v20.11.0\"}",
    recommendation: "Disable debug endpoints in production. Use a global error handler that returns generic error messages. Never expose stack traces or internal paths.",
    cwe: "CWE-209",
    timestamp: "2026-02-26 05:51:40",
  },
  {
    id: "F-007",
    severity: "LOW",
    type: "Missing CORS Policy",
    endpoint: "/api/products",
    method: "GET",
    host: "api.targetapp.dev",
    cvss: 3.7,
    evidence: "Access-Control-Allow-Origin: * returned on authenticated endpoint — allows any origin to read response",
    request: "GET /api/products HTTP/1.1\nHost: api.targetapp.dev\nOrigin: https://evil.com",
    response: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
    recommendation: "Restrict CORS to known origins. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
    cwe: "CWE-942",
    timestamp: "2026-02-26 05:51:44",
  },
  {
    id: "F-008",
    severity: "INFO",
    type: "Endpoint Disclosure",
    endpoint: "/api/internal/debug",
    method: "GET",
    host: "api.targetapp.dev",
    cvss: 2.0,
    evidence: "Unauthenticated access to internal diagnostics endpoint reveals system information",
    request: "GET /api/internal/debug HTTP/1.1\nHost: api.targetapp.dev\n[No auth]",
    response: "HTTP/1.1 200 OK\n\n{\"uptime\":\"14d 3h\",\"memory_usage\":\"412MB\",\"db_connections\":8}",
    recommendation: "Remove or authenticate internal/debug endpoints. Apply IP allowlisting for any necessary diagnostic endpoints.",
    cwe: "CWE-200",
    timestamp: "2026-02-26 05:51:47",
  },
];

const SEV_CLASS: Record<string, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ReportsInteractive() {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<ReportFinding | null>(null);
  const [detailTab, setDetailTab] = useState<"evidence" | "request" | "response" | "fix">("evidence");

  const filtered = ALL_FINDINGS
    .filter((f) => severityFilter === "ALL" || f.severity === severityFilter)
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const severityCounts = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = ALL_FINDINGS.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<string, number>);

  const cvssAvg = (ALL_FINDINGS.reduce((a, f) => a + f.cvss, 0) / ALL_FINDINGS.length).toFixed(1);

  const handleExport = () => {
    const data = JSON.stringify(ALL_FINDINGS, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aase_report_2026-02-26.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const DETAIL_TABS: { id: "evidence" | "request" | "response" | "fix"; label: string }[] = [
    { id: "evidence", label: "Evidence" },
    { id: "request", label: "Request" },
    { id: "response", label: "Response" },
    { id: "fix", label: "Remediation" },
  ];

  return (
    <div className="min-h-screen bg-[#080C0A] pt-16">
      {/* Page header */}
      <div className="border-b border-[rgba(0,230,118,0.08)] bg-[#0D1410]/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-5">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest">
                  aase_report /
                </span>
                <span className="font-mono text-[10px] text-[#00E676] uppercase tracking-widest">
                  mitmproxy_dump_2026-02-26.json
                </span>
              </div>
              <h1 className="font-mono font-bold text-2xl text-[#E8F5E9] tracking-tight">
                Vulnerability Report
              </h1>
              <p className="font-mono text-xs text-[#5A7A65] mt-1">
                Scanned: api.targetapp.dev · 2026-02-26 05:51:12 · 2,104 cases · 10 endpoints
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 px-4 py-2 font-mono text-xs text-[#5A7A65] border border-[rgba(0,230,118,0.12)] rounded hover:text-[#00E676] hover:border-[rgba(0,230,118,0.3)] transition-all uppercase tracking-widest"
              >
                <Icon name="ArrowLeftIcon" size={13} />
                Dashboard
              </Link>
              <button
                onClick={handleExport}
                className="flex items-center gap-1.5 px-4 py-2 font-mono text-xs text-[#00E676] border border-[rgba(0,230,118,0.3)] rounded hover:bg-[rgba(0,230,118,0.08)] transition-all uppercase tracking-widest"
              >
                <Icon name="DocumentArrowDownIcon" size={13} />
                Export JSON
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6">
        {/* Summary severity cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
          {SEV_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? "ALL" : sev)}
              className={`terminal-window p-4 text-left transition-all duration-200 hover:border-[rgba(0,230,118,0.25)] ${
                severityFilter === sev ? "border-[rgba(0,230,118,0.3)] bg-[rgba(0,230,118,0.04)]" : ""
              }`}
            >
              <div
                className={`font-mono text-3xl font-black mb-1 ${
                  sev === "CRITICAL" ?"text-[#FF4F4F]"
                    : sev === "HIGH" ?"text-[#FF8C42]"
                    : sev === "MEDIUM" ?"text-[#FFD166]"
                    : sev === "LOW" ?"text-[#00E676]" :"text-[#4FC3F7]"
                }`}
              >
                {severityCounts[sev]}
              </div>
              <div className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest">{sev}</div>
            </button>
          ))}
        </div>

        {/* Metrics row */}
        <div className="grid grid-cols-3 gap-3 mb-6">
          <div className="terminal-window p-4">
            <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-1">Avg CVSS Score</div>
            <div className="font-mono text-2xl font-bold text-[#FF8C42]">{cvssAvg}</div>
            <div className="font-mono text-[10px] text-[#2E4A38] mt-1">out of 10.0</div>
          </div>
          <div className="terminal-window p-4">
            <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-1">Total Findings</div>
            <div className="font-mono text-2xl font-bold text-[#E8F5E9]">{ALL_FINDINGS.length}</div>
            <div className="font-mono text-[10px] text-[#2E4A38] mt-1">across 10 endpoints</div>
          </div>
          <div className="terminal-window p-4">
            <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-1">Overall Risk</div>
            <div className="font-mono text-2xl font-bold text-[#FF4F4F]">CRITICAL</div>
            <div className="font-mono text-[10px] text-[#2E4A38] mt-1">immediate action required</div>
          </div>
        </div>

        {/* CVSS bar chart */}
        <div className="terminal-window p-5 mb-6">
          <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-4">
            Finding Distribution by Severity
          </div>
          <div className="space-y-3">
            {SEV_ORDER.map((sev) => {
              const count = severityCounts[sev];
              const pct = Math.round((count / ALL_FINDINGS.length) * 100);
              const color =
                sev === "CRITICAL" ? "#FF4F4F" :
                sev === "HIGH" ? "#FF8C42" :
                sev === "MEDIUM" ? "#FFD166" :
                sev === "LOW" ? "#00E676" : "#4FC3F7";
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="font-mono text-[10px] uppercase tracking-wider w-20 text-right flex-shrink-0" style={{ color }}>
                    {sev}
                  </span>
                  <div className="flex-1 h-2 bg-[rgba(0,230,118,0.06)] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${pct}%`, background: color }}
                    />
                  </div>
                  <span className="font-mono text-xs w-6 text-right flex-shrink-0" style={{ color }}>
                    {count}
                  </span>
                  <span className="font-mono text-[10px] text-[#2E4A38] w-8 text-right flex-shrink-0">
                    {pct}%
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity filter pills */}
        <div className="flex items-center gap-2 mb-4 flex-wrap">
          <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest">Filter:</span>
          {["ALL", ...SEV_ORDER].map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`font-mono text-[10px] px-3 py-1 rounded border uppercase tracking-wider transition-all ${
                severityFilter === s
                  ? "bg-[rgba(0,230,118,0.12)] text-[#00E676] border-[rgba(0,230,118,0.3)]"
                  : "text-[#2E4A38] border-transparent hover:text-[#5A7A65] hover:border-[rgba(0,230,118,0.1)]"
              }`}
            >
              {s} {s !== "ALL" && `(${severityCounts[s] ?? 0})`}
            </button>
          ))}
          <span className="font-mono text-[10px] text-[#2E4A38] ml-2">
            Showing {filtered.length} of {ALL_FINDINGS.length}
          </span>
        </div>

        {/* Main layout: table + detail panel */}
        <div className={`grid gap-6 ${selectedFinding ? "grid-cols-1 lg:grid-cols-2" : "grid-cols-1"}`}>
          {/* Findings table */}
          <div className="terminal-window">
            <div className="terminal-header justify-between">
              <div className="flex items-center gap-2">
                <div className="terminal-dot" style={{ background: "#FF5F56" }} />
                <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
                <div className="terminal-dot" style={{ background: "#27C93F" }} />
                <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-2">
                  findings ({filtered.length})
                </span>
              </div>
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest">
                Click row for details
              </span>
            </div>

            {/* Table header */}
            <div className="flex items-center gap-3 px-4 py-2 border-b border-[rgba(0,230,118,0.06)] bg-[rgba(0,230,118,0.02)]">
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest w-16 flex-shrink-0">ID</span>
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest w-24 flex-shrink-0">Severity</span>
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest flex-1">Type · Endpoint</span>
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest w-14 text-right flex-shrink-0">CVSS</span>
            </div>

            <div className="divide-y divide-[rgba(0,230,118,0.04)]">
              {filtered.map((f) => (
                <div
                  key={f.id}
                  className={`endpoint-row flex items-center gap-3 px-4 py-3 cursor-pointer transition-all ${
                    selectedFinding?.id === f.id
                      ? "bg-[rgba(0,230,118,0.06)] border-l-2 border-l-[#00E676]"
                      : "border-l-2 border-l-transparent"
                  }`}
                  onClick={() => {
                    setSelectedFinding(selectedFinding?.id === f.id ? null : f);
                    setDetailTab("evidence");
                  }}
                >
                  <span className="font-mono text-[10px] text-[#2E4A38] w-16 flex-shrink-0">{f.id}</span>
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider w-24 text-center flex-shrink-0 ${SEV_CLASS[f.severity]}`}
                  >
                    {f.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-xs text-[#E8F5E9] font-semibold truncate">{f.type}</div>
                    <div className="font-mono text-[10px] text-[#5A7A65] truncate">
                      {f.method} {f.endpoint}
                    </div>
                  </div>
                  <span
                    className={`font-mono text-sm font-bold w-14 text-right flex-shrink-0 ${
                      f.cvss >= 9
                        ? "text-[#FF4F4F]"
                        : f.cvss >= 7
                        ? "text-[#FF8C42]"
                        : f.cvss >= 4
                        ? "text-[#FFD166]"
                        : "text-[#00E676]"
                    }`}
                  >
                    {f.cvss.toFixed(1)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Detail panel */}
          {selectedFinding && (
            <div className="terminal-window flex flex-col" style={{ minHeight: "500px" }}>
              <div className="terminal-header justify-between">
                <div className="flex items-center gap-2">
                  <div className="terminal-dot" style={{ background: "#FF5F56" }} />
                  <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
                  <div className="terminal-dot" style={{ background: "#27C93F" }} />
                  <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-2">
                    {selectedFinding.id} — detail
                  </span>
                </div>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-[#2E4A38] hover:text-[#5A7A65] transition-colors p-1"
                  aria-label="Close detail panel"
                >
                  <Icon name="XMarkIcon" size={16} />
                </button>
              </div>

              {/* Finding meta header */}
              <div className="px-5 py-4 border-b border-[rgba(0,230,118,0.08)] space-y-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider flex-shrink-0 ${SEV_CLASS[selectedFinding.severity]}`}
                  >
                    {selectedFinding.severity}
                  </span>
                  <span className="font-mono text-sm text-[#E8F5E9] font-bold">{selectedFinding.type}</span>
                  <span className="font-mono text-[10px] text-[#5A7A65] px-2 py-0.5 rounded bg-[rgba(79,195,247,0.08)] border border-[rgba(79,195,247,0.2)] text-[#4FC3F7]">
                    {selectedFinding.cwe}
                  </span>
                  <span
                    className={`font-mono text-base font-black ml-auto flex-shrink-0 ${
                      selectedFinding.cvss >= 9
                        ? "text-[#FF4F4F]"
                        : selectedFinding.cvss >= 7
                        ? "text-[#FF8C42]"
                        : selectedFinding.cvss >= 4
                        ? "text-[#FFD166]"
                        : "text-[#00E676]"
                    }`}
                  >
                    CVSS {selectedFinding.cvss.toFixed(1)}
                  </span>
                </div>

                <div className="flex items-center gap-2 font-mono text-[11px] text-[#5A7A65]">
                  <span className="method-get px-1.5 py-0.5 rounded text-[10px]">{selectedFinding.method}</span>
                  <span className="text-[#E8F5E9]">{selectedFinding.host}</span>
                  <span>{selectedFinding.endpoint}</span>
                </div>

                <div className="font-mono text-[10px] text-[#2E4A38]">
                  Detected: {selectedFinding.timestamp}
                </div>
              </div>

              {/* Detail tabs */}
              <div className="flex border-b border-[rgba(0,230,118,0.08)]">
                {DETAIL_TABS.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setDetailTab(tab.id)}
                    className={`flex-1 py-2.5 font-mono text-[10px] uppercase tracking-widest transition-all ${
                      detailTab === tab.id
                        ? "text-[#00E676] border-b-2 border-[#00E676] bg-[rgba(0,230,118,0.04)]"
                        : "text-[#2E4A38] hover:text-[#5A7A65] border-b-2 border-transparent"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-y-auto p-5">
                {detailTab === "evidence" && (
                  <div className="space-y-4">
                    <div>
                      <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-2">
                        Evidence
                      </div>
                      <div className="bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(0,230,118,0.06)]">
                        <p className="font-mono text-xs text-[#E8F5E9] leading-relaxed">
                          {selectedFinding.evidence}
                        </p>
                      </div>
                    </div>

                    {/* CVSS breakdown bar */}
                    <div>
                      <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-2">
                        CVSS Score Breakdown
                      </div>
                      <div className="bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(0,230,118,0.06)] space-y-2">
                        {[
                          { label: "Attack Vector", value: selectedFinding.cvss >= 9 ? "Network" : "Network", score: selectedFinding.cvss >= 9 ? 1.0 : 0.8 },
                          { label: "Attack Complexity", value: "Low", score: 0.77 },
                          { label: "Privileges Required", value: selectedFinding.cvss >= 8 ? "None" : "Low", score: selectedFinding.cvss >= 8 ? 0.85 : 0.62 },
                          { label: "Confidentiality Impact", value: "High", score: 0.56 },
                        ].map((metric) => (
                          <div key={metric.label} className="flex items-center gap-3">
                            <span className="font-mono text-[10px] text-[#5A7A65] w-36 flex-shrink-0">{metric.label}</span>
                            <div className="flex-1 h-1 bg-[rgba(0,230,118,0.06)] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${metric.score * 100}%`,
                                  background: selectedFinding.cvss >= 9 ? "#FF4F4F" : selectedFinding.cvss >= 7 ? "#FF8C42" : "#FFD166",
                                }}
                              />
                            </div>
                            <span className="font-mono text-[10px] text-[#5A7A65] w-14 text-right flex-shrink-0">
                              {metric.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {detailTab === "request" && (
                  <div>
                    <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-2">
                      Fuzz Request
                    </div>
                    <div className="bg-[rgba(0,0,0,0.5)] rounded p-4 border border-[rgba(0,230,118,0.06)]">
                      <pre className="font-mono text-xs text-[#E8F5E9] whitespace-pre-wrap leading-relaxed">
                        {selectedFinding.request}
                      </pre>
                    </div>
                  </div>
                )}

                {detailTab === "response" && (
                  <div>
                    <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-2">
                      Server Response
                    </div>
                    <div className="bg-[rgba(0,0,0,0.5)] rounded p-4 border border-[rgba(255,79,79,0.1)]">
                      <pre className="font-mono text-xs text-[#E8F5E9] whitespace-pre-wrap leading-relaxed">
                        {selectedFinding.response}
                      </pre>
                    </div>
                  </div>
                )}

                {detailTab === "fix" && (
                  <div className="space-y-4">
                    <div>
                      <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-2">
                        Remediation
                      </div>
                      <div className="bg-[rgba(0,230,118,0.04)] rounded p-4 border border-[rgba(0,230,118,0.12)]">
                        <p className="font-mono text-xs text-[#E8F5E9] leading-relaxed">
                          {selectedFinding.recommendation}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 bg-[rgba(0,0,0,0.4)] rounded p-3 border border-[rgba(0,230,118,0.06)]">
                        <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-1">Reference</div>
                        <div className="font-mono text-xs text-[#4FC3F7]">{selectedFinding.cwe}</div>
                      </div>
                      <div className="flex-1 bg-[rgba(0,0,0,0.4)] rounded p-3 border border-[rgba(0,230,118,0.06)]">
                        <div className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest mb-1">Priority</div>
                        <div
                          className={`font-mono text-xs font-bold ${
                            selectedFinding.severity === "CRITICAL" ?"text-[#FF4F4F]"
                              : selectedFinding.severity === "HIGH" ?"text-[#FF8C42]" :"text-[#FFD166]"
                          }`}
                        >
                          {selectedFinding.severity === "CRITICAL" ?"Fix Immediately"
                            : selectedFinding.severity === "HIGH" ?"Fix This Sprint" :"Fix Next Release"}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Export actions footer */}
        <div className="mt-6 terminal-window p-5">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <div className="font-mono text-xs text-[#E8F5E9] font-semibold mb-1">Export Report</div>
              <div className="font-mono text-[10px] text-[#5A7A65]">
                Download findings for your pentest deliverables
              </div>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              {[
                { label: "JSON", icon: "CodeBracketIcon" },
                { label: "HTML", icon: "DocumentTextIcon" },
                { label: "Markdown", icon: "DocumentIcon" },
                { label: "CSV", icon: "TableCellsIcon" },
              ].map((fmt) => (
                <button
                  key={fmt.label}
                  onClick={handleExport}
                  className="flex items-center gap-1.5 px-4 py-2 font-mono text-xs text-[#5A7A65] border border-[rgba(0,230,118,0.12)] rounded hover:text-[#00E676] hover:border-[rgba(0,230,118,0.3)] hover:bg-[rgba(0,230,118,0.04)] transition-all uppercase tracking-widest"
                >
                  <Icon name={fmt.icon as any} size={13} />
                  {fmt.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}