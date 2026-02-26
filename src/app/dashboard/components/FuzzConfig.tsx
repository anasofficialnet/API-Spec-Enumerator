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
  dryRun: boolean;
  categories: string[];
}

const FUZZ_CATEGORIES = [
  { id: "sqli", label: "SQL Injection", color: "#FF4F4F" },
  { id: "xss", label: "XSS", color: "#FF8C42" },
  { id: "bola", label: "BOLA / IDOR", color: "#FFD166" },
  { id: "ssti", label: "SSTI", color: "#4FC3F7" },
  { id: "path", label: "Path Traversal", color: "#00E676" },
  { id: "auth", label: "Auth Bypass", color: "#A78BFA" },
];

export default function FuzzConfig({ selectedCount, totalCases, onStart, isRunning }: FuzzConfigProps) {
  const [config, setConfig] = useState<FuzzSettings>({
    targetUrl: "https://api.targetapp.dev",
    rateLimit: 10,
    concurrency: 3,
    authHeader: "Authorization",
    authValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    dryRun: false,
    categories: ["sqli", "xss", "bola", "path"],
  });

  const toggleCategory = (id: string) => {
    setConfig((prev) => ({
      ...prev,
      categories: prev.categories.includes(id)
        ? prev.categories.filter((c) => c !== id)
        : [...prev.categories, id],
    }));
  };

  return (
    <div className="terminal-window">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: "#FF5F56" }} />
        <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
        <div className="terminal-dot" style={{ background: "#27C93F" }} />
        <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-3">
          fuzz_config.yaml
        </span>
      </div>

      <div className="p-5 space-y-5">
        {/* Target URL */}
        <div>
          <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-1.5">
            Target Base URL
          </label>
          <input
            type="text"
            value={config.targetUrl}
            onChange={(e) => setConfig((p) => ({ ...p, targetUrl: e.target.value }))}
            className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(0,230,118,0.12)] rounded px-3 py-2 font-mono text-xs text-[#E8F5E9] focus:outline-none focus:border-[rgba(0,230,118,0.4)] transition-colors"
          />
        </div>

        {/* Rate + Concurrency */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-1.5">
              Rate (req/s)
            </label>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min={1}
                max={100}
                value={config.rateLimit}
                onChange={(e) => setConfig((p) => ({ ...p, rateLimit: parseInt(e.target.value) }))}
                className="flex-1 accent-[#00E676]"
              />
              <span className="font-mono text-xs text-[#00E676] w-8 text-right">{config.rateLimit}</span>
            </div>
          </div>
          <div>
            <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-1.5">
              Concurrency
            </label>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min={1}
                max={20}
                value={config.concurrency}
                onChange={(e) => setConfig((p) => ({ ...p, concurrency: parseInt(e.target.value) }))}
                className="flex-1 accent-[#00E676]"
              />
              <span className="font-mono text-xs text-[#00E676] w-8 text-right">{config.concurrency}</span>
            </div>
          </div>
        </div>

        {/* Auth */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-1.5">
              Auth Header
            </label>
            <input
              type="text"
              value={config.authHeader}
              onChange={(e) => setConfig((p) => ({ ...p, authHeader: e.target.value }))}
              className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(0,230,118,0.12)] rounded px-3 py-2 font-mono text-xs text-[#E8F5E9] focus:outline-none focus:border-[rgba(0,230,118,0.4)] transition-colors"
            />
          </div>
          <div>
            <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-1.5">
              Token Value
            </label>
            <input
              type="password"
              value={config.authValue}
              onChange={(e) => setConfig((p) => ({ ...p, authValue: e.target.value }))}
              className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(0,230,118,0.12)] rounded px-3 py-2 font-mono text-xs text-[#E8F5E9] focus:outline-none focus:border-[rgba(0,230,118,0.4)] transition-colors"
            />
          </div>
        </div>

        {/* Categories */}
        <div>
          <label className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest block mb-2">
            Fuzz Categories
          </label>
          <div className="flex flex-wrap gap-2">
            {FUZZ_CATEGORIES.map((cat) => (
              <button
                key={cat.id}
                onClick={() => toggleCategory(cat.id)}
                className={`font-mono text-[10px] px-2.5 py-1 rounded border uppercase tracking-wider transition-all ${
                  config.categories.includes(cat.id)
                    ? "border-current opacity-100" :"opacity-30 border-[rgba(0,230,118,0.1)]"
                }`}
                style={config.categories.includes(cat.id) ? { color: cat.color, borderColor: cat.color, background: `${cat.color}15` } : { color: "#5A7A65" }}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>

        {/* Dry run toggle */}
        <div className="flex items-center justify-between py-2 border-t border-[rgba(0,230,118,0.08)]">
          <div>
            <p className="font-mono text-xs text-[#E8F5E9]">Dry Run Mode</p>
            <p className="font-mono text-[10px] text-[#2E4A38]">Log requests without sending</p>
          </div>
          <button
            onClick={() => setConfig((p) => ({ ...p, dryRun: !p.dryRun }))}
            className={`w-10 h-5 rounded-full transition-all duration-300 relative ${
              config.dryRun ? "bg-[#FFD166]" : "bg-[rgba(0,230,118,0.15)]"
            }`}
          >
            <span
              className={`absolute top-0.5 w-4 h-4 rounded-full transition-all duration-300 ${
                config.dryRun ? "left-5.5 bg-[#080C0A]" : "left-0.5 bg-[#00E676]"
              }`}
              style={{ left: config.dryRun ? "22px" : "2px" }}
            />
          </button>
        </div>

        {/* Summary + Launch */}
        <div className="bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(0,230,118,0.06)] font-mono text-xs space-y-1">
          <div className="text-[#5A7A65]">// campaign summary</div>
          <div><span className="text-[#4FC3F7]">endpoints</span><span className="text-[#5A7A65]">: </span><span className="text-[#00E676]">{selectedCount}</span></div>
          <div><span className="text-[#4FC3F7]">fuzz_cases</span><span className="text-[#5A7A65]">: </span><span className="text-[#00E676]">{totalCases}</span></div>
          <div><span className="text-[#4FC3F7]">rate</span><span className="text-[#5A7A65]">: </span><span className="text-[#00E676]">{config.rateLimit}</span><span className="text-[#5A7A65]">/s</span></div>
          <div><span className="text-[#4FC3F7]">est_duration</span><span className="text-[#5A7A65]">: ~</span><span className="text-[#00E676]">{Math.ceil(totalCases / config.rateLimit)}s</span></div>
        </div>

        <button
          onClick={() => onStart(config)}
          disabled={selectedCount === 0 || isRunning}
          className={`w-full py-3 font-mono text-sm font-bold uppercase tracking-widest rounded transition-all duration-300 flex items-center justify-center gap-2 ${
            selectedCount === 0 || isRunning
              ? "bg-[rgba(0,230,118,0.05)] text-[#2E4A38] cursor-not-allowed border border-[rgba(0,230,118,0.08)]"
              : "hacker-btn w-full"
          }`}
        >
          {isRunning ? (
            <>
              <span className="w-3 h-3 rounded-full border-2 border-[#00E676] border-t-transparent animate-spin" />
              Running...
            </>
          ) : (
            <>
              <Icon name="BoltIcon" size={16} />
              Start Fuzzing
            </>
          )}
        </button>
      </div>
    </div>
  );
}