"use client";

import { useState, useEffect } from "react";
import Icon from "@/components/ui/AppIcon";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { API_BASE, apiFetch } from "@/lib/api";

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

const SEV_CLASS: Record<string, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ReportsInteractive() {
  const params = useSearchParams();
  const scanId = params?.get("scan") ?? null;

  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<ReportFinding | null>(null);
  const [detailTab, setDetailTab] = useState<"evidence" | "request" | "response" | "fix">("evidence");
  const [findings, setFindings] = useState<ReportFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await apiFetch<{ findings: ReportFinding[] }>(`/api/scan/${scanId}/report`);
        setFindings(res.findings || []);
      } catch (err: any) {
        setError(err.message || "Failed to load report");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [scanId]);

  const filtered = findings
    .filter((f) => severityFilter === "ALL" || f.severity === severityFilter)
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const severityCounts = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<string, number>);

  const cvssAvg = findings.length
    ? (findings.reduce((a, f) => a + f.cvss, 0) / findings.length).toFixed(1)
    : "0.0";

  const handleExport = async () => {
    if (!scanId) return;
    try {
      const res = await fetch(`${API_BASE}/api/scan/${scanId}/export.json`);
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aase_report_${scanId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // Fallback: client-side export
      const data = JSON.stringify(findings, null, 2);
      const blob = new Blob([data], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aase_report_${scanId || "scan"}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleExportHtml = async () => {
    if (!scanId) return;
    const res = await fetch(`${API_BASE}/api/scan/${scanId}/export.html`);
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aase_report_${scanId}.html`;
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
    <div className="min-h-screen pt-16">
      {/* Page header */}
      <div className="chrome-bar border-b">
        <div className="max-w-7xl mx-auto px-6 py-5">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest">
                  aase_report /
                </span>
                <span className="font-mono text-[10px] text-[#6366F1] uppercase tracking-widest">
                  {scanId || "no_scan"}
                </span>
              </div>
              <h1 className="font-mono font-bold text-2xl text-[#F8FAFC] tracking-tight">
                Vulnerability Report
              </h1>
              <p className="font-mono text-xs text-[#94A3B8] mt-1">
                {scanId ? `Scan: ${scanId}` : "Load a scan to view findings"}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 px-4 py-2 font-mono text-xs text-[#94A3B8] border border-[rgba(99, 102, 241,0.12)] rounded hover:text-[#6366F1] hover:border-[rgba(99, 102, 241,0.3)] transition-all uppercase tracking-widest"
              >
                <Icon name="ArrowLeftIcon" size={13} />
                Dashboard
              </Link>
              <button
                onClick={handleExport}
                disabled={!findings.length}
                className={`flex items-center gap-1.5 px-4 py-2 font-mono text-xs uppercase tracking-widest rounded ${findings.length
                    ? "text-[#6366F1] border border-[rgba(99, 102, 241,0.3)] hover:bg-[rgba(99, 102, 241,0.08)]"
                    : "text-[#475569] border border-[rgba(99, 102, 241,0.08)] cursor-not-allowed"
                  }`}
              >
                <Icon name="DocumentArrowDownIcon" size={13} />
                Export JSON
              </button>
              <button
                onClick={handleExportHtml}
                disabled={!findings.length || !scanId}
                className={`flex items-center gap-1.5 px-4 py-2 font-mono text-xs uppercase tracking-widest rounded ${findings.length && scanId
                    ? "text-[#4FC3F7] border border-[rgba(79,195,247,0.3)] hover:bg-[rgba(79,195,247,0.08)]"
                    : "text-[#475569] border border-[rgba(99, 102, 241,0.08)] cursor-not-allowed"
                  }`}
              >
                <Icon name="DocumentTextIcon" size={13} />
                Export HTML
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6">
        {loading && (
          <div className="font-mono text-xs text-[#94A3B8]">Loading report...</div>
        )}
        {error && (
          <div className="font-mono text-xs text-[#FF4F4F]">{error}</div>
        )}
        {!scanId && (
          <div className="font-mono text-xs text-[#94A3B8]">No scan id provided.</div>
        )}

        {/* Summary severity cards */}
        {findings.length > 0 && (
          <div className="fade-up grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
            {SEV_ORDER.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? "ALL" : sev)}
                className={`terminal-window p-4 text-left transition-all duration-200 hover:border-[rgba(99, 102, 241,0.25)] ${severityFilter === sev ? "border-[rgba(99, 102, 241,0.3)] bg-[rgba(99, 102, 241,0.04)]" : ""
                  }`}
              >
                <div
                  className={`font-mono text-3xl font-black mb-1 ${sev === "CRITICAL" ? "text-[#FF4F4F]"
                      : sev === "HIGH" ? "text-[#FF8C42]"
                        : sev === "MEDIUM" ? "text-[#FFD166]"
                          : sev === "LOW" ? "text-[#6366F1]" : "text-[#4FC3F7]"
                    }`}
                >
                  {severityCounts[sev]}
                </div>
                <div className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">{sev}</div>
              </button>
            ))}
          </div>
        )}

        {/* Metrics row */}
        {findings.length > 0 && (
          <div className="fade-up stagger-1 grid grid-cols-3 gap-3 mb-6">
            <div className="terminal-window p-4">
              <div className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest mb-1">Avg CVSS Score</div>
              <div className="font-mono text-2xl font-bold text-[#FF8C42]">{cvssAvg}</div>
              <div className="font-mono text-[10px] text-[#475569] mt-1">out of 10.0</div>
            </div>
            <div className="terminal-window p-4">
              <div className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest mb-1">Total Findings</div>
              <div className="font-mono text-2xl font-bold text-[#F8FAFC]">{findings.length}</div>
              <div className="font-mono text-[10px] text-[#475569] mt-1">across endpoints</div>
            </div>
            <div className="terminal-window p-4">
              <div className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest mb-1">Overall Risk</div>
              <div className="font-mono text-2xl font-bold text-[#FF4F4F]">{findings.length ? "ELEVATED" : "NONE"}</div>
              <div className="font-mono text-[10px] text-[#475569] mt-1">review findings</div>
            </div>
          </div>
        )}

        {/* CVSS bar chart */}
        {findings.length > 0 && (
          <div className="terminal-window p-5 mb-6">
            <div className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest mb-4">
              Finding Distribution by Severity
            </div>
            <div className="space-y-3">
              {SEV_ORDER.map((sev) => {
                const count = severityCounts[sev];
                const pct = Math.round((count / findings.length) * 100);
                const color =
                  sev === "CRITICAL" ? "#FF4F4F" :
                    sev === "HIGH" ? "#FF8C42" :
                      sev === "MEDIUM" ? "#FFD166" :
                        sev === "LOW" ? "#6366F1" : "#4FC3F7";
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <span className="font-mono text-[10px] uppercase tracking-wider w-20 text-right flex-shrink-0" style={{ color }}>
                      {sev}
                    </span>
                    <div className="flex-1 h-2 bg-[rgba(99, 102, 241,0.06)] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${pct}%`, background: color }}
                      />
                    </div>
                    <span className="font-mono text-xs w-6 text-right flex-shrink-0" style={{ color }}>
                      {count}
                    </span>
                    <span className="font-mono text-[10px] text-[#475569] w-8 text-right flex-shrink-0">
                      {pct}%
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Severity filter pills */}
        {findings.length > 0 && (
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">Filter:</span>
            {["ALL", ...SEV_ORDER].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`font-mono text-[10px] px-2.5 py-1 rounded border uppercase tracking-wider transition-all ${severityFilter === s ? "border-[#6366F1] text-[#6366F1]" : "border-[rgba(99, 102, 241,0.08)] text-[#94A3B8]"
                  }`}
              >
                {s}
              </button>
            ))}
          </div>
        )}

        {/* Findings list + details */}
        {findings.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left list */}
            <div className="lg:col-span-1 terminal-window p-4 h-[640px] overflow-y-auto">
              <div className="space-y-2">
                {filtered.map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className={`w-full text-left p-3 rounded border transition-all ${selectedFinding?.id === f.id
                        ? "border-[rgba(99, 102, 241,0.3)] bg-[rgba(99, 102, 241,0.04)]"
                        : "border-[rgba(99, 102, 241,0.08)]"
                      }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider ${SEV_CLASS[f.severity]}`}>
                        {f.severity}
                      </span>
                      <span className="font-mono text-xs text-[#F8FAFC]">{f.type}</span>
                    </div>
                    <div className="font-mono text-[10px] text-[#94A3B8] mt-1 truncate">
                      {f.method} {f.endpoint}
                    </div>
                    <div className="font-mono text-[10px] text-[#475569] mt-1 truncate">
                      {f.evidence}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Right detail */}
            <div className="lg:col-span-2 terminal-window p-5 h-[640px]">
              {selectedFinding ? (
                <>
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider ${SEV_CLASS[selectedFinding.severity]}`}>
                          {selectedFinding.severity}
                        </span>
                        <span className="font-mono text-sm text-[#F8FAFC] font-semibold">{selectedFinding.type}</span>
                      </div>
                      <p className="font-mono text-[10px] text-[#94A3B8] mt-1">
                        {selectedFinding.method} {selectedFinding.endpoint} · {selectedFinding.host}
                      </p>
                      <p className="font-mono text-[10px] text-[#475569] mt-2">
                        {selectedFinding.evidence}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="font-mono text-xs text-[#FF8C42]">CVSS {selectedFinding.cvss}</div>
                      <div className="font-mono text-[10px] text-[#475569]">{selectedFinding.cwe}</div>
                      <div className="font-mono text-[10px] text-[#475569]">{selectedFinding.timestamp}</div>
                    </div>
                  </div>

                  <div className="mt-4 flex items-center gap-2">
                    {DETAIL_TABS.map((t) => (
                      <button
                        key={t.id}
                        onClick={() => setDetailTab(t.id)}
                        className={`font-mono text-[10px] px-2.5 py-1 rounded border uppercase tracking-wider transition-all ${detailTab === t.id
                            ? "border-[#6366F1] text-[#6366F1]"
                            : "border-[rgba(99, 102, 241,0.08)] text-[#94A3B8]"
                          }`}
                      >
                        {t.label}
                      </button>
                    ))}
                  </div>

                  <div className="mt-4 h-[440px] overflow-y-auto bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(99, 102, 241,0.06)]">
                    {detailTab === "evidence" && (
                      <pre className="font-mono text-[11px] text-[#F8FAFC] whitespace-pre-wrap">{selectedFinding.evidence}</pre>
                    )}
                    {detailTab === "request" && (
                      <pre className="font-mono text-[11px] text-[#F8FAFC] whitespace-pre-wrap">{selectedFinding.request}</pre>
                    )}
                    {detailTab === "response" && (
                      <pre className="font-mono text-[11px] text-[#F8FAFC] whitespace-pre-wrap">{selectedFinding.response}</pre>
                    )}
                    {detailTab === "fix" && (
                      <pre className="font-mono text-[11px] text-[#F8FAFC] whitespace-pre-wrap">{selectedFinding.recommendation}</pre>
                    )}
                  </div>
                </>
              ) : (
                <div className="h-full flex items-center justify-center">
                  <span className="font-mono text-xs text-[#475569]">Select a finding</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
