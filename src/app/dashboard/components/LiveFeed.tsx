"use client";

import { useEffect, useRef } from "react";
import Icon from "@/components/ui/AppIcon";

export interface Finding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  type: string;
  endpoint: string;
  method: string;
  evidence: string;
  timestamp: string;
}

interface LiveFeedProps {
  findings: Finding[];
  isRunning: boolean;
  progress: number;
  casesRun: number;
  totalCases: number;
}

const SEV_CLASS: Record<string, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

const SEV_ICON: Record<string, string> = {
  CRITICAL: "ExclamationCircleIcon",
  HIGH: "ExclamationTriangleIcon",
  MEDIUM: "InformationCircleIcon",
  LOW: "CheckCircleIcon",
  INFO: "InformationCircleIcon",
};

export default function LiveFeed({ findings, isRunning, progress, casesRun, totalCases }: LiveFeedProps) {
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [findings]);

  return (
    <div className="terminal-window flex flex-col h-full">
      <div className="terminal-header justify-between">
        <div className="flex items-center gap-2">
          <div className="terminal-dot" style={{ background: "#FF5F56" }} />
          <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
          <div className="terminal-dot" style={{ background: "#27C93F" }} />
          <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-2">
            live_findings
          </span>
        </div>
        <div className="flex items-center gap-3">
          {isRunning && (
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00E676] animate-pulse" />
              <span className="font-mono text-[10px] text-[#00E676] uppercase tracking-widest">
                scanning
              </span>
            </div>
          )}
          <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest">
            {findings.length} findings
          </span>
        </div>
      </div>

      {/* Progress bar */}
      {(isRunning || progress > 0) && (
        <div className="px-4 py-3 border-b border-[rgba(0,230,118,0.06)] space-y-2">
          <div className="flex justify-between font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest">
            <span>{casesRun} / {totalCases} cases</span>
            <span>{progress}%</span>
          </div>
          <div className="h-1 bg-[rgba(0,230,118,0.08)] rounded-full overflow-hidden">
            <div
              className="h-full bg-[#00E676] rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Findings feed */}
      <div ref={feedRef} className="flex-1 overflow-y-auto p-4 space-y-2">
        {findings.length === 0 && !isRunning && (
          <div className="flex flex-col items-center justify-center h-40 gap-3 text-center">
            <div className="w-10 h-10 rounded border border-[rgba(0,230,118,0.12)] bg-[rgba(0,230,118,0.04)] flex items-center justify-center">
              <Icon name="MagnifyingGlassIcon" size={20} className="text-[#2E4A38]" />
            </div>
            <p className="font-mono text-xs text-[#2E4A38] uppercase tracking-widest">
              Awaiting scan
            </p>
          </div>
        )}

        {findings.map((f) => (
          <div
            key={f.id}
            className="terminal-window p-3 hover:border-[rgba(0,230,118,0.2)] transition-all duration-200 cursor-default fade-in-up"
          >
            <div className="flex items-start gap-3">
              <span className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider flex-shrink-0 ${SEV_CLASS[f.severity]}`}>
                {f.severity}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="font-mono text-xs text-[#E8F5E9] font-semibold">{f.type}</span>
                  <span className="font-mono text-[10px] text-[#2E4A38]">·</span>
                  <span className="font-mono text-[10px] text-[#5A7A65] truncate">{f.method} {f.endpoint}</span>
                </div>
                <p className="font-mono text-[10px] text-[#2E4A38] truncate">{f.evidence}</p>
              </div>
              <span className="font-mono text-[10px] text-[#2E4A38] flex-shrink-0">{f.timestamp}</span>
            </div>
          </div>
        ))}

        {isRunning && (
          <div className="flex items-center gap-2 py-2">
            <span className="w-2 h-4 bg-[#00E676] cursor-blink" />
            <span className="font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest animate-pulse">
              Probing endpoints...
            </span>
          </div>
        )}
      </div>

      {/* Summary bar */}
      {findings.length > 0 && (
        <div className="px-4 py-3 border-t border-[rgba(0,230,118,0.08)] flex items-center gap-4 flex-wrap">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
            const count = findings.filter((f) => f.severity === sev).length;
            if (count === 0) return null;
            return (
              <div key={sev} className="flex items-center gap-1.5">
                <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${SEV_CLASS[sev]}`}>{sev}</span>
                <span className="font-mono text-xs text-[#5A7A65]">{count}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}