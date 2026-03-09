"use client";

import { useState } from "react";
import Icon from "@/components/ui/AppIcon";

interface FuzzConfigProps {
  selectedCount: number;
  totalCases: number;
  onStart: (config: FuzzSettings) => void;
  isRunning: boolean;
}

export interface FuzzSettings {
  targetUrl: string;
  rateLimit: number;
  concurrency: number;
  authHeader: string;
  authValue: string;
  cookieString: string;
  dryRun: boolean;
  aggressive: boolean;
  categories: string[];
  customHeaders?: Record<string, string>;
  customCookies?: Record<string, string>;
  enableBola?: boolean;
  bolaUserBToken?: string;
  enableStateful?: boolean;
  enableRace?: boolean;
  burstSize?: number;
  enableMutations?: boolean;
  enableGraphql?: boolean;
}

const FUZZ_CATEGORIES = [
  { id: "auth", label: "Auth Checks", color: "#FF8C42" },
  { id: "hidden_params", label: "Hidden Params", color: "#4FC3F7" },
  { id: "cors", label: "CORS", color: "#6366F1" },
  { id: "error_leak", label: "Verbose Errors", color: "#FFD166" },
  { id: "sqli", label: "SQLi Payloads", color: "#FF4F4F" },
  { id: "xss", label: "XSS Payloads", color: "#A78BFA" },
  { id: "ssti", label: "SSTI Payloads", color: "#7DD3FC" },
];

export default function FuzzConfig({ selectedCount, totalCases, onStart, isRunning }: FuzzConfigProps) {
  const [config, setConfig] = useState<FuzzSettings>({
    targetUrl: "https://api.targetapp.dev",
    rateLimit: 2,
    concurrency: 1,
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
  });

  const toggleCategory = (id: string) => {
    setConfig((prev) => ({
      ...prev,
      categories: prev.categories.includes(id)
        ? prev.categories.filter((c) => c !== id)
        : [...prev.categories, id],
    }));
  };

  const updateCustomHeaders = (value: string) => {
    try {
      const parsed = value.trim() ? JSON.parse(value) : {};
      setConfig((p) => ({ ...p, customHeaders: parsed }));
    } catch {
      setConfig((p) => ({ ...p, customHeaders: p.customHeaders }));
    }
  };

  const projectedTotalCases = totalCases
    + (config.enableBola ? selectedCount * 1 : 0)
    + (config.enableStateful ? selectedCount * 4 : 0) // rough upper bound
    + (config.enableRace ? selectedCount * (config.burstSize || 10) : 0)
    + (config.enableMutations ? selectedCount * 7 : 0)
    + (config.enableGraphql ? selectedCount * 5 : 0);

  return (
    <div className="terminal-window">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: "#FF5F56" }} />
        <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
        <div className="terminal-dot" style={{ background: "#27C93F" }} />
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest ml-3">
          ADVANCED_CONFIG
        </span>
      </div>

      <div className="p-5 space-y-5">
        {/* Target URL */}
        <div>
          <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1.5">
            Target Base URL (Allowlist)
          </label>
          <input
            type="text"
            value={config.targetUrl}
            onChange={(e) => setConfig((p) => ({ ...p, targetUrl: e.target.value }))}
            className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors"
          />
          <p className="font-mono text-[10px] text-[#475569] mt-1">
            Only this domain will be scanned. Requests outside allowlist are blocked.
          </p>
        </div>

        {/* Auth */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1.5">
              Auth Header
            </label>
            <input
              type="text"
              value={config.authHeader}
              onChange={(e) => setConfig((p) => ({ ...p, authHeader: e.target.value }))}
              className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors"
            />
          </div>
          <div>
            <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1.5">
              Token Value
            </label>
            <input
              type="password"
              value={config.authValue}
              onChange={(e) => setConfig((p) => ({ ...p, authValue: e.target.value }))}
              className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors"
            />
          </div>
        </div>

        <div>
          <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1.5">
            Cookies (key=value; key=value)
          </label>
          <input
            type="text"
            value={config.cookieString}
            onChange={(e) => setConfig((p) => ({ ...p, cookieString: e.target.value }))}
            className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors"
          />
        </div>

        <div>
          <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1.5">
            Custom Headers (JSON)
          </label>
          <textarea
            rows={3}
            placeholder='{"X-Api-Key":"..."}'
            onChange={(e) => updateCustomHeaders(e.target.value)}
            className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors"
          />
        </div>

        {/* Categories */}
        <div>
          <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-2">
            Probe Categories
          </label>
          <div className="flex flex-wrap gap-2">
            {FUZZ_CATEGORIES.map((cat) => (
              <button
                key={cat.id}
                onClick={() => toggleCategory(cat.id)}
                className={`font-mono text-[10px] px-2.5 py-1 rounded border uppercase tracking-wider transition-all ${config.categories.includes(cat.id)
                  ? "border-current opacity-100" : "opacity-30 border-[rgba(99, 102, 241,0.1)]"
                  }`}
                style={config.categories.includes(cat.id) ? { color: cat.color, borderColor: cat.color, background: `${cat.color}15` } : { color: "#94A3B8" }}
              >
                {cat.label}
              </button>
            ))}
          </div>
          <p className="font-mono text-[10px] text-[#475569] mt-2">
            Payload categories only run in Aggressive Mode.
          </p>
        </div>

        {/* Aggressive toggle */}
        <div className="flex items-center justify-between py-2 border-t border-[rgba(99, 102, 241,0.08)]">
          <div>
            <p className="font-mono text-xs text-[#F8FAFC]">Aggressive Mode</p>
            <p className="font-mono text-[10px] text-[#475569]">Enables SQLi/XSS/SSTI payload probes</p>
          </div>
          <button
            onClick={() => setConfig((p) => ({ ...p, aggressive: !p.aggressive }))}
            className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.aggressive ? "bg-[#FF4F4F]" : "bg-[rgba(99, 102, 241,0.15)]"
              }`}
          >
            <span
              className={`absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 ${config.aggressive ? "left-5.5 bg-[#030509]" : "left-0.5 bg-[#6366F1]"
                }`}
              style={{ left: config.aggressive ? "22px" : "2px" }}
            />
          </button>
        </div>

        {/* Dry run toggle */}
        <div className="flex items-center justify-between py-2 border-t border-[rgba(99, 102, 241,0.08)]">
          <div>
            <p className="font-mono text-xs text-[#F8FAFC]">Dry Run Mode</p>
            <p className="font-mono text-[10px] text-[#475569]">Log requests without sending</p>
          </div>
          <button
            onClick={() => setConfig((p) => ({ ...p, dryRun: !p.dryRun }))}
            className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.dryRun ? "bg-[#FFD166]" : "bg-[rgba(99, 102, 241,0.15)]"
              }`}
          >
            <span
              className={`absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 ${config.dryRun ? "left-5.5 bg-[#030509]" : "left-0.5 bg-[#6366F1]"
                }`}
              style={{ left: config.dryRun ? "22px" : "2px" }}
            />
          </button>
        </div>

        {/* ── Power Features ── */}
        <div className="border-t border-[rgba(99, 102, 241,0.15)] pt-4">
          <div className="flex items-center gap-2 mb-3">
            <Icon name="BoltIcon" size={14} className="text-[#A78BFA]" />
            <span className="font-mono text-[10px] text-[#A78BFA] uppercase tracking-widest font-bold">Power Features</span>
          </div>

          {/* BOLA/IDOR Toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="font-mono text-xs text-[#F8FAFC]">🧠 BOLA/IDOR Detection</p>
              <p className="font-mono text-[10px] text-[#475569]">Cross-user resource access testing</p>
            </div>
            <button
              onClick={() => setConfig((p) => ({ ...p, enableBola: !p.enableBola }))}
              className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.enableBola ? "bg-[#A78BFA]" : "bg-[rgba(99,102,241,0.15)]"}`}
            >
              <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 bg-[#030509]" style={{ left: config.enableBola ? "22px" : "2px" }} />
            </button>
          </div>
          {config.enableBola && (
            <div className="ml-4 mb-2">
              <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1">User B Token (attacker)</label>
              <input type="password" value={config.bolaUserBToken} onChange={(e) => setConfig((p) => ({ ...p, bolaUserBToken: e.target.value }))}
                className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(167,139,250,0.2)] rounded px-3 py-1.5 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(167,139,250,0.5)] transition-colors"
                placeholder="Bearer token for User B" />
              <p className="font-mono text-[10px] text-[#475569] mt-0.5">User A = your main auth above</p>
            </div>
          )}

          {/* Stateful Toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="font-mono text-xs text-[#F8FAFC]">🔗 Stateful Fuzzing</p>
              <p className="font-mono text-[10px] text-[#475569]">Skip-step & replay logic attacks</p>
            </div>
            <button
              onClick={() => setConfig((p) => ({ ...p, enableStateful: !p.enableStateful }))}
              className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.enableStateful ? "bg-[#A78BFA]" : "bg-[rgba(99,102,241,0.15)]"}`}
            >
              <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 bg-[#030509]" style={{ left: config.enableStateful ? "22px" : "2px" }} />
            </button>
          </div>

          {/* Race Condition Toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="font-mono text-xs text-[#F8FAFC]">🏎️ Race Condition</p>
              <p className="font-mono text-[10px] text-[#475569]">Concurrent burst testing</p>
            </div>
            <button
              onClick={() => setConfig((p) => ({ ...p, enableRace: !p.enableRace }))}
              className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.enableRace ? "bg-[#A78BFA]" : "bg-[rgba(99,102,241,0.15)]"}`}
            >
              <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 bg-[#030509]" style={{ left: config.enableRace ? "22px" : "2px" }} />
            </button>
          </div>
          {config.enableRace && (
            <div className="ml-4 mb-2">
              <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-1">Burst Size</label>
              <input type="number" min={2} max={50} value={config.burstSize} onChange={(e) => setConfig((p) => ({ ...p, burstSize: parseInt(e.target.value) || 10 }))}
                className="w-20 bg-[rgba(0,0,0,0.4)] border border-[rgba(167,139,250,0.2)] rounded px-3 py-1.5 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(167,139,250,0.5)] transition-colors" />
            </div>
          )}

          {/* AST Mutations Toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="font-mono text-xs text-[#F8FAFC]">🧬 JSON Mutations</p>
              <p className="font-mono text-[10px] text-[#475569]">Type-swap, nesting, mass-assign</p>
            </div>
            <button
              onClick={() => setConfig((p) => ({ ...p, enableMutations: !p.enableMutations }))}
              className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.enableMutations ? "bg-[#A78BFA]" : "bg-[rgba(99,102,241,0.15)]"}`}
            >
              <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 bg-[#030509]" style={{ left: config.enableMutations ? "22px" : "2px" }} />
            </button>
          </div>

          {/* GraphQL/WS Toggle */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="font-mono text-xs text-[#F8FAFC]">🕸️ GraphQL & WebSocket</p>
              <p className="font-mono text-[10px] text-[#475569]">Introspection, depth DoS, CSWSH</p>
            </div>
            <button
              onClick={() => setConfig((p) => ({ ...p, enableGraphql: !p.enableGraphql }))}
              className={`w-10 h-5 rounded-full transition-all duration-300 relative ${config.enableGraphql ? "bg-[#A78BFA]" : "bg-[rgba(99,102,241,0.15)]"}`}
            >
              <span className="absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 bg-[#030509]" style={{ left: config.enableGraphql ? "22px" : "2px" }} />
            </button>
          </div>
        </div>

        {/* Summary + Launch */}
        <div className="bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(99, 102, 241,0.06)] font-mono text-xs space-y-1">
          <div className="text-[#94A3B8]">// campaign summary</div>
          <div><span className="text-[#4FC3F7]">endpoints</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{selectedCount}</span></div>
          <div>
            <span className="text-[#4FC3F7]">fuzz_cases</span><span className="text-[#94A3B8]">: </span>
            <span className="text-[#6366F1]">
              {projectedTotalCases > totalCases ? `~${projectedTotalCases.toLocaleString()}` : totalCases.toLocaleString()}
            </span>
          </div>
          <div><span className="text-[#4FC3F7]">mode</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{config.dryRun ? "dry_run" : "live"}</span></div>
        </div>

        <button
          onClick={() => onStart(config)}
          disabled={selectedCount === 0 || isRunning}
          className={`w-full py-3 font-mono text-sm font-bold uppercase tracking-widest rounded transition-all duration-300 flex items-center justify-center gap-2 ${selectedCount === 0 || isRunning
            ? "bg-[rgba(99, 102, 241,0.05)] text-[#475569] cursor-not-allowed border border-[rgba(99, 102, 241,0.08)]"
            : "hacker-btn w-full"
            }`}
        >
          {isRunning ? (
            <>
              <span className="w-3 h-3 rounded-full border-2 border-[#6366F1] border-t-transparent animate-spin" />
              Running...
            </>
          ) : (
            <>
              <Icon name="BoltIcon" size={16} />
              Start Scan
            </>
          )}
        </button>
      </div>
    </div>
  );
}
