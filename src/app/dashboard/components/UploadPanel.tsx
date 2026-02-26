"use client";

import { useState, useRef, useCallback } from "react";
import Icon from "@/components/ui/AppIcon";

interface UploadPanelProps {
  onUploadComplete: (data: TrafficData) => void;
}

export interface TrafficData {
  fileName: string;
  format: "mitmproxy" | "burp";
  transactions: number;
  hosts: string[];
  endpoints: EndpointData[];
}

export interface EndpointData {
  id: string;
  method: string;
  path: string;
  host: string;
  statusCodes: number[];
  authRequired: boolean;
  paramCount: number;
  bodyFields: string[];
  schemaConfidence: number;
  fuzzCases: number;
}

const MOCK_DATA: TrafficData = {
  fileName: "mitmproxy_dump_2026-02-26.json",
  format: "mitmproxy",
  transactions: 1847,
  hosts: ["api.targetapp.dev", "auth.targetapp.dev", "cdn.targetapp.dev"],
  endpoints: [
    { id: "ep-1", method: "POST", path: "/api/auth/login", host: "auth.targetapp.dev", statusCodes: [200, 401], authRequired: false, paramCount: 2, bodyFields: ["email", "password"], schemaConfidence: 98, fuzzCases: 84 },
    { id: "ep-2", method: "GET", path: "/api/users", host: "api.targetapp.dev", statusCodes: [200, 403], authRequired: true, paramCount: 3, bodyFields: [], schemaConfidence: 95, fuzzCases: 62 },
    { id: "ep-3", method: "GET", path: "/api/users/{id}", host: "api.targetapp.dev", statusCodes: [200, 404], authRequired: true, paramCount: 1, bodyFields: [], schemaConfidence: 97, fuzzCases: 55 },
    { id: "ep-4", method: "PUT", path: "/api/users/{id}", host: "api.targetapp.dev", statusCodes: [200, 400, 403], authRequired: true, paramCount: 1, bodyFields: ["email", "role", "age"], schemaConfidence: 91, fuzzCases: 148 },
    { id: "ep-5", method: "DELETE", path: "/api/users/{id}", host: "api.targetapp.dev", statusCodes: [204, 403], authRequired: true, paramCount: 1, bodyFields: [], schemaConfidence: 99, fuzzCases: 38 },
    { id: "ep-6", method: "POST", path: "/api/orders", host: "api.targetapp.dev", statusCodes: [201, 400], authRequired: true, paramCount: 0, bodyFields: ["items", "address", "coupon"], schemaConfidence: 88, fuzzCases: 196 },
    { id: "ep-7", method: "GET", path: "/api/orders/{id}", host: "api.targetapp.dev", statusCodes: [200, 404], authRequired: true, paramCount: 1, bodyFields: [], schemaConfidence: 96, fuzzCases: 44 },
    { id: "ep-8", method: "GET", path: "/api/products", host: "api.targetapp.dev", statusCodes: [200], authRequired: false, paramCount: 5, bodyFields: [], schemaConfidence: 94, fuzzCases: 78 },
    { id: "ep-9", method: "POST", path: "/api/admin/users", host: "api.targetapp.dev", statusCodes: [201, 403], authRequired: true, paramCount: 0, bodyFields: ["email", "role", "permissions"], schemaConfidence: 82, fuzzCases: 210 },
    { id: "ep-10", method: "GET", path: "/api/internal/debug", host: "api.targetapp.dev", statusCodes: [200], authRequired: false, paramCount: 0, bodyFields: [], schemaConfidence: 75, fuzzCases: 22 },
  ],
};

export default function UploadPanel({ onUploadComplete }: UploadPanelProps) {
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const simulateUpload = useCallback(() => {
    setUploading(true);
    setProgress(0);
    const stages = [
      { label: "Parsing transactions...", pct: 20 },
      { label: "Discovering endpoints...", pct: 45 },
      { label: "Inferring schemas...", pct: 70 },
      { label: "Generating fuzz cases...", pct: 90 },
      { label: "Complete!", pct: 100 },
    ];
    let i = 0;
    const tick = () => {
      if (i < stages.length) {
        setStage(stages[i].label);
        setProgress(stages[i].pct);
        i++;
        setTimeout(tick, 600);
      } else {
        setTimeout(() => {
          setUploading(false);
          onUploadComplete(MOCK_DATA);
        }, 400);
      }
    };
    tick();
  }, [onUploadComplete]);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      simulateUpload();
    },
    [simulateUpload]
  );

  return (
    <div className="terminal-window">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: "#FF5F56" }} />
        <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
        <div className="terminal-dot" style={{ background: "#27C93F" }} />
        <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-3">
          ingest_traffic.sh
        </span>
      </div>

      <div className="p-6">
        {!uploading ? (
          <>
            {/* Drop zone */}
            <div
              className={`upload-zone rounded-lg p-10 flex flex-col items-center justify-center gap-4 cursor-pointer ${dragOver ? "drag-over" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => inputRef.current?.click()}
            >
              <input ref={inputRef} type="file" className="hidden" accept=".json,.xml,.har" onChange={simulateUpload} />
              <div className="w-14 h-14 rounded border border-[rgba(0,230,118,0.25)] bg-[rgba(0,230,118,0.06)] flex items-center justify-center">
                <Icon name="ArrowUpTrayIcon" size={26} className="text-[#00E676]" />
              </div>
              <div className="text-center">
                <p className="font-mono text-sm text-[#E8F5E9] font-semibold mb-1">
                  Drop traffic capture here
                </p>
                <p className="font-mono text-xs text-[#5A7A65]">
                  mitmproxy JSON · Burp Suite XML · HAR
                </p>
              </div>
              <div className="flex gap-2 flex-wrap justify-center">
                {["mitmproxy", "Burp Suite", "HAR"].map((f) => (
                  <span key={f} className="font-mono text-[10px] px-2 py-0.5 rounded bg-[rgba(0,230,118,0.06)] text-[#5A7A65] border border-[rgba(0,230,118,0.1)] uppercase tracking-wider">
                    {f}
                  </span>
                ))}
              </div>
            </div>

            {/* Or use demo */}
            <div className="mt-4 flex items-center gap-3">
              <div className="h-px flex-1 bg-[rgba(0,230,118,0.08)]" />
              <span className="font-mono text-[10px] text-[#2E4A38] uppercase">or</span>
              <div className="h-px flex-1 bg-[rgba(0,230,118,0.08)]" />
            </div>
            <button
              className="mt-4 w-full py-3 font-mono text-xs text-[#5A7A65] border border-[rgba(0,230,118,0.1)] rounded hover:text-[#00E676] hover:border-[rgba(0,230,118,0.3)] transition-all uppercase tracking-widest"
              onClick={simulateUpload}
            >
              Load Demo Capture (1,847 transactions)
            </button>
          </>
        ) : (
          <div className="py-8 space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-[#00E676] animate-pulse" />
              <span className="font-mono text-xs text-[#00E676] uppercase tracking-widest">{stage}</span>
            </div>
            <div className="h-1.5 bg-[rgba(0,230,118,0.08)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[#00E676] rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="font-mono text-[10px] text-[#2E4A38] text-right">{progress}%</div>
          </div>
        )}
      </div>
    </div>
  );
}