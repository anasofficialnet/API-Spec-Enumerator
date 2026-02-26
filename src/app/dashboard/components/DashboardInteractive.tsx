"use client";

import { useState, useCallback } from "react";
import UploadPanel, { TrafficData, EndpointData } from "./UploadPanel";
import EndpointList from "./EndpointList";
import FuzzConfig, { FuzzSettings } from "./FuzzConfig";
import LiveFeed, { Finding } from "./LiveFeed";
import Icon from "@/components/ui/AppIcon";
import Link from "next/link";

const MOCK_FINDINGS: Finding[] = [
  { id: "f-1", severity: "CRITICAL", type: "SQL Injection", endpoint: "/api/users", method: "GET", evidence: "param id=' OR 1=1-- returned 200 with 847 rows", timestamp: "05:51:14" },
  { id: "f-2", severity: "HIGH", type: "BOLA / IDOR", endpoint: "/api/orders/{id}", method: "GET", evidence: "User A accessed User B's order #4821 (403→200)", timestamp: "05:51:18" },
  { id: "f-3", severity: "HIGH", type: "Auth Bypass", endpoint: "/api/admin/users", method: "POST", evidence: "Removed Authorization header → 201 Created", timestamp: "05:51:22" },
  { id: "f-4", severity: "MEDIUM", type: "Missing Rate Limit", endpoint: "/api/auth/login", method: "POST", evidence: "500 requests in 10s — no throttling observed", timestamp: "05:51:29" },
  { id: "f-5", severity: "MEDIUM", type: "Mass Assignment", endpoint: "/api/users/{id}", method: "PUT", evidence: "Setting role=admin in body accepted (200 OK)", timestamp: "05:51:33" },
  { id: "f-6", severity: "LOW", type: "Verbose Error", endpoint: "/api/internal/debug", method: "GET", evidence: "Stack trace leaked: node_modules/express/lib/router", timestamp: "05:51:40" },
  { id: "f-7", severity: "LOW", type: "Missing CORS Policy", endpoint: "/api/products", method: "GET", evidence: "Access-Control-Allow-Origin: * on authenticated endpoint", timestamp: "05:51:44" },
  { id: "f-8", severity: "INFO", type: "Endpoint Disclosure", endpoint: "/api/internal/debug", method: "GET", evidence: "Unauthenticated endpoint returns internal diagnostics", timestamp: "05:51:47" },
];

type Tab = "upload" | "endpoints" | "fuzz" | "findings";

export default function DashboardInteractive() {
  const [trafficData, setTrafficData] = useState<TrafficData | null>(null);
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("upload");
  const [isRunning, setIsRunning] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [progress, setProgress] = useState(0);
  const [casesRun, setCasesRun] = useState(0);

  const handleUploadComplete = useCallback((data: TrafficData) => {
    setTrafficData(data);
    setSelectedEndpoints(data.endpoints.map((e) => e.id));
    setActiveTab("endpoints");
  }, []);

  const handleStartFuzz = useCallback((config: FuzzSettings) => {
    setIsRunning(true);
    setFindings([]);
    setProgress(0);
    setCasesRun(0);
    setActiveTab("findings");

    const totalCases = trafficData?.endpoints
      .filter((e) => selectedEndpoints.includes(e.id))
      .reduce((a, e) => a + e.fuzzCases, 0) ?? 937;

    let findingIdx = 0;
    let casesDone = 0;

    const interval = setInterval(() => {
      casesDone = Math.min(casesDone + Math.floor(Math.random() * 40 + 10), totalCases);
      const pct = Math.round((casesDone / totalCases) * 100);
      setProgress(pct);
      setCasesRun(casesDone);

      // Drip findings
      if (findingIdx < MOCK_FINDINGS.length && Math.random() > 0.5) {
        setFindings((prev) => [...prev, MOCK_FINDINGS[findingIdx]]);
        findingIdx++;
      }

      if (casesDone >= totalCases) {
        clearInterval(interval);
        // Add remaining findings
        const remaining = MOCK_FINDINGS.slice(findingIdx);
        remaining.forEach((f, i) => {
          setTimeout(() => {
            setFindings((prev) => [...prev, f]);
          }, i * 200);
        });
        setTimeout(() => setIsRunning(false), remaining.length * 200 + 400);
      }
    }, 300);
  }, [trafficData, selectedEndpoints]);

  const TABS: { id: Tab; label: string; icon: string; count?: number; disabled?: boolean }[] = [
    { id: "upload", label: "Ingest", icon: "ArrowUpTrayIcon" },
    { id: "endpoints", label: "Endpoints", icon: "ListBulletIcon", count: trafficData?.endpoints.length, disabled: !trafficData },
    { id: "fuzz", label: "Fuzz Config", icon: "BoltIcon", disabled: !trafficData },
    { id: "findings", label: "Findings", icon: "ExclamationTriangleIcon", count: findings.length, disabled: !trafficData },
  ];

  const selectedEpData = trafficData?.endpoints.filter((e) => selectedEndpoints.includes(e.id)) ?? [];
  const totalSelectedCases = selectedEpData.reduce((a, e) => a + e.fuzzCases, 0);

  return (
    <div className="min-h-screen bg-[#080C0A] pt-16">
      {/* Top bar */}
      <div className="border-b border-[rgba(0,230,118,0.08)] bg-[#0D1410]/50 backdrop-blur-sm sticky top-16 z-30">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between h-12">
          <div className="flex items-center gap-1">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => !tab.disabled && setActiveTab(tab.id)}
                disabled={tab.disabled}
                className={`flex items-center gap-1.5 px-4 py-2 font-mono text-[11px] uppercase tracking-widest transition-all ${
                  activeTab === tab.id
                    ? "text-[#00E676] border-b-2 border-[#00E676]"
                    : tab.disabled
                    ? "text-[#2E4A38] cursor-not-allowed"
                    : "text-[#5A7A65] hover:text-[#00E676] border-b-2 border-transparent"
                }`}
              >
                <Icon name={tab.icon as any} size={13} />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 rounded-full bg-[rgba(0,230,118,0.12)] text-[#00E676] text-[9px] font-bold">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3">
            {trafficData && (
              <div className="flex items-center gap-2 font-mono text-[10px] text-[#5A7A65]">
                <Icon name="DocumentIcon" size={12} />
                <span className="text-[#00E676]">{trafficData.fileName}</span>
                <span>·</span>
                <span>{trafficData.transactions.toLocaleString()} txns</span>
              </div>
            )}
            {findings.length > 0 && (
              <Link
                href="/reports"
                className="flex items-center gap-1.5 px-3 py-1 font-mono text-[10px] text-[#00E676] border border-[rgba(0,230,118,0.2)] rounded hover:bg-[rgba(0,230,118,0.08)] transition-all uppercase tracking-widest"
              >
                <Icon name="DocumentArrowDownIcon" size={12} />
                View Report
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="max-w-7xl mx-auto px-6 py-6">
        {/* Stats bar (when data loaded) */}
        {trafficData && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { label: "Endpoints", value: trafficData.endpoints.length, icon: "ListBulletIcon", color: "#4FC3F7" },
              { label: "Selected", value: selectedEndpoints.length, icon: "CheckCircleIcon", color: "#00E676" },
              { label: "Fuzz Cases", value: totalSelectedCases, icon: "BeakerIcon", color: "#FF8C42" },
              { label: "Findings", value: findings.length, icon: "ExclamationTriangleIcon", color: findings.some((f) => f.severity === "CRITICAL") ? "#FF4F4F" : "#FFD166" },
            ].map((stat) => (
              <div key={stat.label} className="terminal-window p-4 flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded flex items-center justify-center flex-shrink-0"
                  style={{ background: `${stat.color}15`, border: `1px solid ${stat.color}30` }}
                >
                  <Icon name={stat.icon as any} size={18} style={{ color: stat.color }} />
                </div>
                <div>
                  <div className="font-mono text-xl font-bold" style={{ color: stat.color }}>
                    {stat.value.toLocaleString()}
                  </div>
                  <div className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest">{stat.label}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab content */}
        {activeTab === "upload" && (
          <div className="max-w-2xl mx-auto">
            <UploadPanel onUploadComplete={handleUploadComplete} />
          </div>
        )}

        {activeTab === "endpoints" && trafficData && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" style={{ minHeight: "600px" }}>
            <div className="lg:col-span-2" style={{ height: "600px" }}>
              <EndpointList
                endpoints={trafficData.endpoints}
                selected={selectedEndpoints}
                onSelectionChange={setSelectedEndpoints}
              />
            </div>
            <div>
              <FuzzConfig
                selectedCount={selectedEndpoints.length}
                totalCases={totalSelectedCases}
                onStart={handleStartFuzz}
                isRunning={isRunning}
              />
            </div>
          </div>
        )}

        {activeTab === "fuzz" && trafficData && (
          <div className="max-w-xl mx-auto">
            <FuzzConfig
              selectedCount={selectedEndpoints.length}
              totalCases={totalSelectedCases}
              onStart={handleStartFuzz}
              isRunning={isRunning}
            />
          </div>
        )}

        {activeTab === "findings" && (
          <div style={{ height: "600px" }}>
            <LiveFeed
              findings={findings}
              isRunning={isRunning}
              progress={progress}
              casesRun={casesRun}
              totalCases={totalSelectedCases || 937}
            />
          </div>
        )}
      </div>
    </div>
  );
}