"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import UploadPanel, { TrafficData, EndpointData } from "./UploadPanel";
import EndpointList from "./EndpointList";
import FuzzConfig, { FuzzSettings } from "./FuzzConfig";
import LiveFeed, { Finding } from "./LiveFeed";
import Icon from "@/components/ui/AppIcon";
import Link from "next/link";
import { apiFetch } from "@/lib/api";

interface ScanStatus {
  isRunning: boolean;
  progress: number;
  casesRun: number;
  totalCases: number;
  findings: Finding[];
}

type Tab = "upload" | "endpoints" | "fuzz" | "findings";

export default function DashboardInteractive() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [trafficData, setTrafficData] = useState<TrafficData | null>(null);
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("upload");
  const [isRunning, setIsRunning] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [progress, setProgress] = useState(0);
  const [casesRun, setCasesRun] = useState(0);
  const [totalCases, setTotalCases] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const handleUploadComplete = useCallback((data: TrafficData) => {
    setTrafficData(data);
    setScanId(data.scanId);
    setSelectedEndpoints(data.endpoints.map((e) => e.id));
    setActiveTab("endpoints");
    setFindings([]);
    setProgress(0);
    setCasesRun(0);
    setTotalCases(0);
    setError(null);
  }, []);

  const buildAuthConfig = (config: FuzzSettings) => {
    const auth: { bearer?: string; headers?: Record<string, string>; cookies?: Record<string, string> } = {};
    if (config.authHeader && config.authValue) {
      if (config.authHeader.toLowerCase() === "authorization") {
        const val = config.authValue.trim();
        if (val.toLowerCase().startsWith("bearer ")) {
          auth.bearer = val.slice(7).trim();
        } else {
          auth.headers = { Authorization: val };
        }
      } else {
        auth.headers = { [config.authHeader]: config.authValue };
      }
    }
    if (config.cookieString) {
      const cookies: Record<string, string> = {};
      config.cookieString.split(";").forEach((pair) => {
        const [k, v] = pair.split("=");
        if (k && v) cookies[k.trim()] = v.trim();
      });
      auth.cookies = cookies;
    }
    return Object.keys(auth).length ? auth : null;
  };

  const handleStartFuzz = useCallback(async (config: FuzzSettings) => {
    if (!scanId) {
      setError("No scan loaded");
      return;
    }
    setError(null);
    setIsRunning(true);
    setFindings([]);
    setProgress(0);
    setCasesRun(0);
    setActiveTab("findings");

    let allowlist: string[] = [];
    let targetBase: string | null = null;
    try {
      const url = new URL(config.targetUrl);
      allowlist = [url.hostname];
      targetBase = config.targetUrl;
    } catch {
      setIsRunning(false);
      setError("Invalid target URL");
      return;
    }

    try {
      await apiFetch(`/api/scan/${scanId}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          selected_endpoints: selectedEndpoints,
          config: {
            allowlist,
            target_base_url: targetBase,
            rate_limit: config.rateLimit,
            concurrency: config.concurrency,
            respect_robots: true,
            aggressive: config.aggressive,
            auth: buildAuthConfig(config),
            custom_headers: config.customHeaders || {},
            custom_cookies: config.customCookies || {},
            dry_run: config.dryRun,
            categories: config.categories,
          },
        }),
      });
    } catch (err: any) {
      setIsRunning(false);
      setError(err.message || "Failed to start scan");
      return;
    }

    const fetchStatus = async () => {
      if (!scanId) return;
      try {
        const status = await apiFetch<any>(`/api/scan/${scanId}/status`);
        setIsRunning(status.isRunning);
        setProgress(status.progress);
        setCasesRun(status.casesRun);
        setTotalCases(status.totalCases);

        let allFindings: Finding[] = status.findings || [];
        if (config.dryRun && status.dry_run_log) {
          const dryLog = status.dry_run_log.map((log: any, i: number) => ({
            id: `dry-${i}`,
            severity: "INFO",
            type: "Dry Run (Skipped)",
            endpoint: log.url,
            method: log.method,
            evidence: `Case ${log.id} for ${log.ep_key}`,
            timestamp: new Date().toLocaleTimeString(),
          }));
          allFindings = [...allFindings, ...dryLog];
        }
        setFindings(allFindings);
      } catch (err: any) {
        setError(err.message || "Failed to fetch status");
      }
    };

    await fetchStatus();

    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(fetchStatus, 1000);
  }, [scanId, selectedEndpoints]);

  useEffect(() => {
    if (!isRunning && pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, [isRunning]);

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
  }, []);

  const TABS: { id: Tab; label: string; icon: string; count?: number; disabled?: boolean }[] = [
    { id: "upload", label: "Ingest", icon: "ArrowUpTrayIcon" },
    { id: "endpoints", label: "Endpoints", icon: "ListBulletIcon", count: trafficData?.endpoints.length, disabled: !trafficData },
    { id: "fuzz", label: "Fuzz Config", icon: "BoltIcon", disabled: !trafficData },
    { id: "findings", label: "Findings", icon: "ExclamationTriangleIcon", count: findings.length, disabled: !trafficData },
  ];

  const selectedEpData: EndpointData[] = trafficData?.endpoints.filter((e) => selectedEndpoints.includes(e.id)) ?? [];
  const totalSelectedCases = selectedEpData.reduce((a, e) => a + e.fuzzCases, 0);

  return (
    <div className="min-h-screen pt-16">
      {/* Top bar */}
      <div className="chrome-bar border-b sticky top-16 z-30">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between h-12">
          <div className="flex items-center gap-1">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => !tab.disabled && setActiveTab(tab.id)}
                disabled={tab.disabled}
                className={`flex items-center gap-1.5 px-4 py-2 font-mono text-[11px] uppercase tracking-widest transition-all ${activeTab === tab.id
                    ? "text-[#6366F1] border-b-2 border-[#6366F1]"
                    : tab.disabled
                      ? "text-[#475569] cursor-not-allowed"
                      : "text-[#94A3B8] hover:text-[#6366F1] border-b-2 border-transparent"
                  }`}
              >
                <Icon name={tab.icon as any} size={13} />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 rounded-full bg-[rgba(99, 102, 241,0.12)] text-[#6366F1] text-[9px] font-bold">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3">
            {trafficData && (
              <div className="flex items-center gap-2 font-mono text-[10px] text-[#94A3B8]">
                <Icon name="DocumentIcon" size={12} />
                <span className="text-[#6366F1]">{trafficData.fileName}</span>
                <span>·</span>
                <span>{trafficData.transactions.toLocaleString()} txns</span>
              </div>
            )}
            {findings.length > 0 && scanId && (
              <Link
                href={`/reports?scan=${scanId}`}
                className="flex items-center gap-1.5 px-3 py-1 font-mono text-[10px] text-[#6366F1] border border-[rgba(99, 102, 241,0.2)] rounded hover:bg-[rgba(99, 102, 241,0.08)] transition-all uppercase tracking-widest"
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
        {error && (
          <div className="mb-4 font-mono text-xs text-[#FF4F4F]">
            {error}
          </div>
        )}

        {/* Stats bar (when data loaded) */}
        {trafficData && (
          <div className="fade-up grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            {[
              { label: "Endpoints", value: trafficData.endpoints.length, icon: "ListBulletIcon", color: "#4FC3F7" },
              { label: "Selected", value: selectedEndpoints.length, icon: "CheckCircleIcon", color: "#6366F1" },
              { label: "Fuzz Cases", value: totalSelectedCases, icon: "BeakerIcon", color: "#FF8C42" },
              { label: "Findings", value: findings.length, icon: "ExclamationTriangleIcon", color: findings.some((f) => f.severity === "CRITICAL") ? "#FF4F4F" : "#FFD166" },
            ].map((stat) => (
              <div key={stat.label} className="terminal-window glass-card p-4 flex items-center gap-3">
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
                  <div className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">{stat.label}</div>
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
              totalCases={totalCases || totalSelectedCases || 0}
            />
          </div>
        )}
      </div>
    </div>
  );
}
