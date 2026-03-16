"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import UploadPanel, { TrafficData, EndpointData } from "./UploadPanel";
import EndpointList from "./EndpointList";
import FuzzConfig, { FuzzSettings } from "./FuzzConfig";
import LiveFeed, { Finding } from "./LiveFeed";
import AttackGraphPanel, { AttackGraphData } from "./AttackGraphPanel";
import { applyScanPreset, buildScanValidation } from "./scanConfigUtils";
import Icon from "@/components/ui/AppIcon";
import { apiFetch, apiUrl } from "@/lib/api";
import Link from "next/link";

interface ScanStatus {
  isRunning: boolean;
  isCancelled?: boolean;
  progress: number;
  casesRun: number;
  totalCases: number;
  findings: Finding[];
  dry_run_log?: Array<{ id: string; method: string; url: string; ep_key: string }>;
  lastError?: string | null;
}

interface ScanPreview {
  totalCases: number;
  endpointCases: Record<string, number>;
}

type Tab = "upload" | "endpoints" | "graph" | "fuzz" | "findings" | "shadow" | "patches" | "oast";
type ScanPreset = "safe" | "standard" | "aggressive";

export const DEFAULT_FUZZ_CONFIG: FuzzSettings = {
  targetUrl: "http://127.0.0.1:8055",
  rateLimit: 2,
  concurrency: 1,
  maxRetries: 2,
  authHeader: "Authorization",
  authValue: "",
  cookieString: "",
  dryRun: false,
  aggressive: false,
  categories: ["auth", "hidden_params", "cors", "error_leak"],
  customHeaders: {},
  customCookies: {},
  enableBola: false,
  bolaUserBToken: "",
  enableStateful: false,
  enableRace: false,
  burstSize: 10,
  enableMutations: false,
  enableGraphql: false,
  enableAttackGraph: false,
  enableAutoLogin: false,
  loginUrl: "",
  loginUser: "",
  loginPass: "",
  enableWafEvasion: false,
  enableOast: false,
  oastCallbackUrl: "http://127.0.0.1:8010",
};

export default function DashboardInteractive() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [trafficData, setTrafficData] = useState<TrafficData | null>(null);
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("upload");
  const [isRunning, setIsRunning] = useState(false);
  const [isCancelled, setIsCancelled] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [progress, setProgress] = useState(0);
  const [casesRun, setCasesRun] = useState(0);
  const [totalCases, setTotalCases] = useState(0);
  const [previewCases, setPreviewCases] = useState<Record<string, number>>({});
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const streamRef = useRef<EventSource | null>(null);
  const [shadowReport, setShadowReport] = useState<any>(null);
  const [patches, setPatches] = useState<any[]>([]);
  const [attackGraph, setAttackGraph] = useState<AttackGraphData | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [oastCallbacks, setOastCallbacks] = useState<any[]>([]);
  const [passiveRecon, setPassiveRecon] = useState<any>(null);
  const [subdomainData, setSubdomainData] = useState<any>(null);
  const [jwtAnalysis, setJwtAnalysis] = useState<any>(null);
  const [paramDiscovery, setParamDiscovery] = useState<any>(null);
  const [reconLoading, setReconLoading] = useState(false);
  const [jwtLoading, setJwtLoading] = useState(false);
  const [fuzzConfig, setFuzzConfig] = useState<FuzzSettings>(DEFAULT_FUZZ_CONFIG);
  const [activePreset, setActivePreset] = useState<ScanPreset>("safe");
  const selectedEpData: EndpointData[] = trafficData?.endpoints.filter((e) => selectedEndpoints.includes(e.id)) ?? [];
  const totalSelectedCases = selectedEpData.reduce((sum, endpoint) => (
    sum + (previewCases[endpoint.id] ?? endpoint.fuzzCases)
  ), 0);
  const scanValidation = buildScanValidation(fuzzConfig, {
    selectedEndpoints: selectedEpData,
    capabilities: trafficData?.capabilities,
  });

  const clearLiveUpdates = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.close();
      streamRef.current = null;
    }
  }, []);

  const handleUploadComplete = useCallback((data: TrafficData) => {
    clearLiveUpdates();
    setTrafficData(data);
    setScanId(data.scanId);
    setSelectedEndpoints(data.endpoints.map((e) => e.id));
    setActiveTab("endpoints");
    setFindings([]);
    setProgress(0);
    setCasesRun(0);
    setTotalCases(0);
    setPreviewCases({});
    setIsCancelled(false);
    setAttackGraph(null);
    setError(null);

    // Auto-populate the Target Base URL from the ingested traffic
    const inferredHost = data.hosts && data.hosts.length > 0 ? data.hosts[0] : "";
    const inferredScheme = inferredHost.includes("127.0.0.1") || inferredHost.includes("localhost") ? "http" : "https";
    const autoTarget = inferredHost ? `${inferredScheme}://${inferredHost}` : DEFAULT_FUZZ_CONFIG.targetUrl;
    setActivePreset("safe");
    setFuzzConfig(applyScanPreset({
      ...DEFAULT_FUZZ_CONFIG,
      targetUrl: autoTarget,
    }, "safe", { capabilities: data.capabilities }));
  }, [clearLiveUpdates]);

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

  const buildRunPayload = useCallback(() => {
    const url = new URL(fuzzConfig.targetUrl);
    return {
      selected_endpoints: selectedEndpoints,
      config: {
        allowlist: [url.hostname],
        target_base_url: fuzzConfig.targetUrl,
        rate_limit: fuzzConfig.rateLimit,
        concurrency: fuzzConfig.concurrency,
        max_retries: fuzzConfig.maxRetries ?? 2,
        respect_robots: true,
        aggressive: fuzzConfig.aggressive,
        auth: buildAuthConfig(fuzzConfig),
        custom_headers: fuzzConfig.customHeaders || {},
        custom_cookies: fuzzConfig.customCookies || {},
        dry_run: fuzzConfig.dryRun,
        categories: fuzzConfig.categories,
        enable_bola: fuzzConfig.enableBola,
        bola_config: fuzzConfig.enableBola && fuzzConfig.bolaUserBToken ? {
          user_a_auth: buildAuthConfig(fuzzConfig),
          user_b_auth: { bearer: fuzzConfig.bolaUserBToken },
        } : null,
        enable_stateful: fuzzConfig.enableStateful,
        enable_race: fuzzConfig.enableRace,
        burst_size: fuzzConfig.burstSize,
        enable_mutations: fuzzConfig.enableMutations,
        enable_graphql: fuzzConfig.enableGraphql,
        enable_attack_graph: fuzzConfig.enableAttackGraph,
        enable_auto_login: fuzzConfig.enableAutoLogin,
        login_config: fuzzConfig.enableAutoLogin && fuzzConfig.loginUrl && fuzzConfig.loginUser && fuzzConfig.loginPass ? {
          login_url: fuzzConfig.loginUrl,
          username: fuzzConfig.loginUser,
          password: fuzzConfig.loginPass,
        } : null,
        enable_waf_evasion: fuzzConfig.enableWafEvasion,
        enable_oast: fuzzConfig.enableOast,
        oast_callback_base_url: fuzzConfig.oastCallbackUrl || null,
      },
    };
  }, [fuzzConfig, selectedEndpoints]);

  const applyStatus = useCallback((status: ScanStatus) => {
    setIsRunning(status.isRunning);
    setIsCancelled(Boolean(status.isCancelled));
    setProgress(status.progress);
    setCasesRun(status.casesRun);
    setTotalCases(status.totalCases);
    if (status.lastError) {
      setError(status.lastError);
    }

    // Mark scan as completed when it transitions from running to stopped
    if (!status.isRunning && status.totalCases > 0 && status.casesRun >= status.totalCases) {
      setActiveTab("findings");
      // Auto-run JWT analysis after scan completes
      if (scanId) {
        apiFetch<any>(`/api/scan/${scanId}/jwt-analysis`, {
          method: "POST", headers: {"Content-Type":"application/json"},
          body: JSON.stringify({ test_url: fuzzConfig.targetUrl || null }),
        }).then((data) => {
          setJwtAnalysis(data);
          if (data?.attacks) {
            const jwtFindings = data.attacks
              .filter((a: any) => a.success)
              .map((a: any, idx: number) => ({
                id: `jwt-${idx}`,
                severity: "HIGH" as const,
                type: `JWT ${a.attack_type}`,
                endpoint: fuzzConfig.targetUrl || "auth",
                method: "AUTH",
                evidence: `${a.detail} (status: ${a.attack_status})`,
                timestamp: new Date().toLocaleTimeString(),
              }));
            if (jwtFindings.length > 0) {
              setFindings((prev) => [...prev, ...jwtFindings]);
            }
          }
        }).catch(() => { /* JWT analysis is best-effort */ });
      }
    }

    let allFindings: Finding[] = status.findings || [];
    if (fuzzConfig.dryRun && status.dry_run_log) {
      const dryLog = status.dry_run_log.map((log, i) => ({
        id: `dry-${i}`,
        severity: "INFO" as const,
        type: "Dry Run (Skipped)",
        endpoint: log.url,
        method: log.method,
        evidence: `Case ${log.id} for ${log.ep_key}`,
        timestamp: new Date().toLocaleTimeString(),
      }));
      allFindings = [...allFindings, ...dryLog];
    }
    setFindings(allFindings);
  }, [fuzzConfig.dryRun, fuzzConfig.targetUrl, scanId]);

  const fetchStatusOnce = useCallback(async () => {
    if (!scanId) {
      return;
    }
    try {
      const status = await apiFetch<ScanStatus>(`/api/scan/${scanId}/status`);
      applyStatus(status);
    } catch (err: any) {
      setError(err.message || "Failed to fetch status");
    }
  }, [applyStatus, scanId]);

  const loadAttackGraph = useCallback(async () => {
    if (!scanId) return;
    setGraphLoading(true);
    try {
      const graph = await apiFetch<AttackGraphData>(`/api/scan/${scanId}/attack-graph`);
      setAttackGraph(graph);
    } catch (err: any) {
      setError(err.message || "Failed to load attack graph");
    } finally {
      setGraphLoading(false);
    }
  }, [scanId]);

  const startPolling = useCallback(() => {
    if (!scanId) return;

    void fetchStatusOnce();
    clearLiveUpdates();
    pollRef.current = setInterval(() => {
      void fetchStatusOnce();
    }, 1000);
  }, [clearLiveUpdates, fetchStatusOnce, scanId]);

  const startLiveUpdates = useCallback(() => {
    if (!scanId) return;

    clearLiveUpdates();
    if (typeof window === "undefined" || typeof EventSource === "undefined") {
      startPolling();
      return;
    }

    const stream = new EventSource(apiUrl(`/api/scan/${scanId}/events`));
    streamRef.current = stream;
    stream.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as ScanStatus & { done?: boolean };
        if (!payload.done) {
          applyStatus(payload);
        }
        if (payload.done || (!payload.isRunning && payload.totalCases > 0 && payload.casesRun >= payload.totalCases)) {
          stream.close();
          streamRef.current = null;
          void fetchStatusOnce();
        }
      } catch {
        // Fall back to polling if the stream payload becomes invalid.
        stream.close();
        streamRef.current = null;
        startPolling();
      }
    };
    stream.onerror = () => {
      stream.close();
      streamRef.current = null;
      startPolling();
    };
  }, [applyStatus, clearLiveUpdates, fetchStatusOnce, scanId, startPolling]);

  const handleStartFuzz = useCallback(async () => {
    if (!scanId) {
      setError("No scan loaded");
      return;
    }
    if (scanValidation.hasBlockingIssues) {
      setError(scanValidation.blockers[0]?.message || "Fix the scan configuration before starting.");
      return;
    }
    setError(null);
    setIsRunning(true);
    setFindings([]);
    setProgress(0);
    setCasesRun(0);
    setIsCancelled(false);
    setAttackGraph(null);
    setActiveTab("findings");
    clearLiveUpdates();

    let payload;
    try {
      payload = buildRunPayload();
    } catch {
      setIsRunning(false);
      setError("Invalid target URL");
      return;
    }

    try {
      await apiFetch(`/api/scan/${scanId}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (err: any) {
      setIsRunning(false);
      setError(err.message || "Failed to start scan");
      return;
    }

    startLiveUpdates();
  }, [buildRunPayload, clearLiveUpdates, scanId, scanValidation, startLiveUpdates]);

  const handleCancelScan = useCallback(async () => {
    if (!scanId || !isRunning) {
      return;
    }
    try {
      await apiFetch(`/api/scan/${scanId}/cancel`, {
        method: "POST",
      });
      setIsCancelled(true);
      startPolling();
    } catch (err: any) {
      setError(err.message || "Failed to cancel scan");
    }
  }, [isRunning, scanId, startPolling]);

  useEffect(() => {
    if (!isRunning) {
      clearLiveUpdates();
    }
  }, [clearLiveUpdates, isRunning]);

  useEffect(() => () => {
    clearLiveUpdates();
  }, [clearLiveUpdates]);

  useEffect(() => {
    if (!scanId || isRunning) {
      return;
    }

    if (scanValidation.hasBlockingIssues) {
      setPreviewCases({});
      setTotalCases(0);
      return;
    }

    let cancelled = false;
    const controller = new AbortController();

    const loadPreview = async () => {
      let payload;
      try {
        payload = buildRunPayload();
      } catch {
        if (!cancelled) {
          setPreviewCases({});
          setTotalCases(0);
        }
        return;
      }

      try {
        const res = await fetch(apiUrl(`/api/scan/${scanId}/preview`), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        if (!res.ok) {
          throw new Error(await res.text());
        }
        const preview = await res.json() as ScanPreview;
        if (!cancelled) {
          setPreviewCases(preview.endpointCases || {});
          setTotalCases(preview.totalCases || 0);
        }
      } catch (err: any) {
        if (!cancelled && err.name !== "AbortError") {
          setPreviewCases({});
          setTotalCases(0);
          setError(err.message || "Failed to preview scan");
        }
      }
    };

    void loadPreview();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [buildRunPayload, isRunning, scanId, scanValidation.hasBlockingIssues]);

  useEffect(() => {
    if (!scanId || isRunning) {
      return;
    }
    void loadAttackGraph();
  }, [isRunning, loadAttackGraph, scanId]);

  const TABS: { id: Tab; label: string; icon: string; count?: number; disabled?: boolean }[] = [
    { id: "upload", label: "Ingest", icon: "ArrowUpTrayIcon" },
    { id: "endpoints", label: "Endpoints", icon: "ListBulletIcon", count: trafficData?.endpoints.length, disabled: !trafficData },
    { id: "graph", label: "Attack Graph", icon: "ShareIcon", count: attackGraph?.paths.length, disabled: !trafficData },
    { id: "fuzz", label: "Fuzz Config", icon: "BoltIcon", disabled: !trafficData },
    { id: "findings", label: "Findings", icon: "ExclamationTriangleIcon", count: findings.length, disabled: !trafficData },
    { id: "shadow" as Tab, label: "Shadow API", icon: "EyeSlashIcon", disabled: !trafficData },
    { id: "patches" as Tab, label: "Patches", icon: "WrenchScrewdriverIcon", count: patches.length, disabled: !trafficData || findings.length === 0 },
    { id: "oast" as Tab, label: "OAST", icon: "RocketLaunchIcon", count: oastCallbacks.length, disabled: !trafficData || !fuzzConfig.enableOast },
  ];

  const handleApplyPreset = useCallback((preset: ScanPreset) => {
    setActivePreset(preset);
    setFuzzConfig((prev) => applyScanPreset(prev, preset, {
      selectedEndpoints: selectedEpData,
      capabilities: trafficData?.capabilities,
    }));
  }, [selectedEpData, trafficData?.capabilities]);

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
                className="flex items-center gap-1.5 px-3 py-1 font-mono text-[10px] text-[#6366F1] border border-[rgba(99,102,241,0.3)] rounded hover:bg-[rgba(99,102,241,0.08)] transition-all uppercase tracking-widest font-bold"
              >
                <Icon name="DocumentTextIcon" size={12} />
                View Full Report
              </Link>
            )}
            {findings.length > 0 && scanId && (
              <a
                href={apiUrl(`/api/scan/${scanId}/export.html`)}
                download={`aase_report_${scanId}.html`}
                className="flex items-center gap-1.5 px-3 py-1 font-mono text-[10px] text-[#030509] bg-[#00E676] rounded hover:bg-[#B9FBC0] hover:shadow-[0_0_15px_rgba(0,230,118,0.4)] transition-all uppercase tracking-widest font-bold"
              >
                <Icon name="DocumentArrowDownIcon" size={12} />
                Download Executive Report
              </a>
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
                caseCountOverrides={previewCases}
                selected={selectedEndpoints}
                onSelectionChange={setSelectedEndpoints}
              />
            </div>
            <div>
              <FuzzConfig
                config={fuzzConfig}
                setConfig={setFuzzConfig}
                selectedCount={selectedEndpoints.length}
                totalCases={totalSelectedCases}
                preset={activePreset}
                onApplyPreset={handleApplyPreset}
                validation={scanValidation}
                onStart={handleStartFuzz}
                isRunning={isRunning}
              />
            </div>
          </div>
        )}

        {activeTab === "fuzz" && trafficData && (
          <div className="max-w-xl mx-auto">
            <FuzzConfig
              config={fuzzConfig}
              setConfig={setFuzzConfig}
              selectedCount={selectedEndpoints.length}
              totalCases={totalSelectedCases}
              preset={activePreset}
              onApplyPreset={handleApplyPreset}
              validation={scanValidation}
              onStart={handleStartFuzz}
              isRunning={isRunning}
            />
          </div>
        )}

        {activeTab === "graph" && trafficData && (
          <AttackGraphPanel graph={attackGraph} loading={graphLoading} />
        )}

        {activeTab === "findings" && (
          <div style={{ height: "600px" }}>
            <LiveFeed
              findings={findings}
              isRunning={isRunning}
              isCancelled={isCancelled}
              progress={progress}
              casesRun={casesRun}
              totalCases={totalCases || totalSelectedCases || 0}
              onCancel={handleCancelScan}
            />
          </div>
        )}

        {activeTab === "shadow" && scanId && (
          <div className="max-w-2xl mx-auto space-y-4">
            <div className="terminal-window p-5">
              <h3 className="font-mono text-xs text-[#A78BFA] uppercase tracking-widest mb-3">Shadow API Diff</h3>
              <p className="font-mono text-[10px] text-[#475569] mb-4">Upload an OpenAPI/Swagger spec to compare against captured traffic.</p>
              <input type="file" accept=".json,.yaml,.yml" onChange={async (e) => {
                const file = e.target.files?.[0]; if (!file) return;
                const fd = new FormData(); fd.append("file", file);
                try {
                  const data = await apiFetch<any>(`/api/scan/${scanId}/openapi`, { method: "POST", body: fd });
                  setShadowReport(data);
                } catch (err: any) { setError(err.message); }
              }} className="font-mono text-xs text-[#94A3B8]" />
              {shadowReport && (
                <div className="mt-4 space-y-3">
                  <div className="font-mono text-xs text-[#F8FAFC]">Coverage: <span className="text-[#6366F1]">{shadowReport.coverage_percent}%</span></div>
                  {shadowReport.undocumented?.length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] text-[#FF4F4F] uppercase mb-1">Undocumented (Shadow) Endpoints</div>
                      {shadowReport.undocumented.map((e: any, i: number) => (
                        <div key={i} className="font-mono text-xs text-[#F8FAFC] py-1">{e.method} {e.path} <span className="text-[#475569]">{e.host}</span></div>
                      ))}
                    </div>
                  )}
                  {shadowReport.unimplemented?.length > 0 && (
                    <div>
                      <div className="font-mono text-[10px] text-[#FFD166] uppercase mb-1">In Spec but Not in Traffic</div>
                      {shadowReport.unimplemented.map((e: any, i: number) => (
                        <div key={i} className="font-mono text-xs text-[#94A3B8] py-1">{e.method} {e.path}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "patches" && scanId && (
          <div className="max-w-3xl mx-auto space-y-4">
            <button onClick={async () => {
              try {
                const data = await apiFetch<any>(`/api/scan/${scanId}/patches`);
                setPatches(data.patches || []);
              } catch (err: any) { setError(err.message); }
            }} className="hacker-btn px-4 py-2 font-mono text-xs uppercase tracking-widest">
              Generate Patches ({findings.length} findings)
            </button>
            {patches.map((p, i) => (
              <div key={i} className="terminal-window p-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider badge-${p.severity?.toLowerCase()}`}>{p.severity}</span>
                  <span className="font-mono text-xs text-[#F8FAFC] font-semibold">{p.title}</span>
                  <span className="font-mono text-[10px] text-[#475569]">{p.language}</span>
                </div>
                <p className="font-mono text-[10px] text-[#94A3B8] mb-2">{p.description}</p>
                <pre className="bg-[rgba(0,0,0,0.5)] border border-[rgba(99,102,241,0.1)] rounded p-3 font-mono text-[11px] text-[#E8F5E9] overflow-x-auto whitespace-pre-wrap">{p.code}</pre>
              </div>
            ))}
          </div>
        )}

        {activeTab === "oast" && scanId && (
          <div className="max-w-2xl mx-auto space-y-4">
            <div className="terminal-window p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-mono text-xs text-[#FF4F4F] uppercase tracking-widest">OAST Callback Log</h3>
                <button onClick={async () => {
                  try {
                    const data = await apiFetch<any>(`/api/scan/${scanId}/oast`);
                    setOastCallbacks(data.callbacks || []);
                  } catch (err: any) { setError(err.message); }
                }} className="px-3 py-1 font-mono text-[10px] text-[#FF4F4F] border border-[rgba(255,79,79,0.25)] rounded hover:bg-[rgba(255,79,79,0.08)] transition-all uppercase tracking-widest">
                  Refresh
                </button>
              </div>
              <p className="font-mono text-[10px] text-[#475569] mb-4">Out-of-band callback interactions received by the OAST listener. Enable OAST in Fuzz Config and run a scan to see results.</p>
              {oastCallbacks.length === 0 && (
                <div className="font-mono text-xs text-[#475569] py-8 text-center">No OAST callbacks received yet.</div>
              )}
              {oastCallbacks.map((cb: any, i: number) => (
                <div key={i} className="terminal-window p-3 mb-2">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider badge-high">OAST</span>
                    <span className="font-mono text-xs text-[#F8FAFC] font-semibold">{cb.method || "GET"} {cb.path || cb.token || "unknown"}</span>
                  </div>
                  <div className="font-mono text-[10px] text-[#94A3B8]">{cb.source_ip || ""} · {cb.timestamp || ""}</div>
                  {cb.headers && (
                    <pre className="mt-2 bg-[rgba(0,0,0,0.4)] rounded p-2 font-mono text-[10px] text-[#4FC3F7] whitespace-pre-wrap overflow-x-auto">{typeof cb.headers === "string" ? cb.headers : JSON.stringify(cb.headers, null, 2)}</pre>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}


      </div>
    </div>
  );
}
