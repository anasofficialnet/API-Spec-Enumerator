"use client";

import { useState, useRef, useCallback } from "react";
import Icon from "@/components/ui/AppIcon";
import { API_BASE } from "@/lib/api";

interface UploadPanelProps {
  onUploadComplete: (data: TrafficData) => void;
}

export interface TrafficData {
  scanId: string;
  fileName: string;
  format: "mitmproxy" | "burp" | "har" | "jsonl" | "raw_http" | string;
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

type UploadMode = "file" | "paste";

export default function UploadPanel({ onUploadComplete }: UploadPanelProps) {
  const [mode, setMode] = useState<UploadMode>("file");
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pasteText, setPasteText] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const animateProgress = (onDone?: () => void) => {
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
        setTimeout(tick, 350);
      } else {
        onDone?.();
      }
    };
    tick();
  };

  const handleResponse = (data: any) => {
    setUploading(false);
    onUploadComplete({
      scanId: data.scan_id,
      fileName: data.fileName,
      format: data.format,
      transactions: data.transactions,
      hosts: data.hosts,
      endpoints: data.endpoints,
    });
  };

  const uploadCapture = useCallback(async (file: File) => {
    setError(null);
    setUploading(true);
    setProgress(0);
    animateProgress();

    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${API_BASE}/api/ingest`, {
        method: "POST",
        body: form,
      });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(msg || "Upload failed");
      }
      handleResponse(await res.json());
    } catch (err: any) {
      setUploading(false);
      setError(err.message || "Upload failed");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onUploadComplete]);

  const submitPaste = useCallback(async () => {
    if (!pasteText.trim()) {
      setError("Paste some raw HTTP requests first");
      return;
    }
    setError(null);
    setUploading(true);
    setProgress(0);
    animateProgress();

    try {
      const res = await fetch(`${API_BASE}/api/ingest/paste`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: pasteText }),
      });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(msg || "Parse failed");
      }
      handleResponse(await res.json());
    } catch (err: any) {
      setUploading(false);
      setError(err.message || "Parse failed");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pasteText, onUploadComplete]);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const dropped = e.dataTransfer.files?.[0];
      if (dropped) uploadCapture(dropped);
    },
    [uploadCapture]
  );

  return (
    <div className="terminal-window">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: "#FF5F56" }} />
        <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
        <div className="terminal-dot" style={{ background: "#27C93F" }} />
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest ml-3">
          ingest_traffic.sh
        </span>
      </div>

      {/* Mode tabs */}
      <div className="flex border-b border-[rgba(99, 102, 241,0.08)]">
        {(["file", "paste"] as UploadMode[]).map((m) => (
          <button
            key={m}
            onClick={() => { setMode(m); setError(null); }}
            className={`px-5 py-2.5 font-mono text-[10px] uppercase tracking-widest transition-all ${mode === m
              ? "text-[#6366F1] border-b-2 border-[#6366F1]"
              : "text-[#94A3B8] border-b-2 border-transparent hover:text-[#6366F1]"
              }`}
          >
            {m === "file" ? "Upload File" : "Paste HTTP"}
          </button>
        ))}
      </div>

      <div className="p-6">
        {!uploading ? (
          <>
            {mode === "file" && (
              <>
                {/* Drop zone */}
                <div
                  className={`upload-zone rounded-lg p-10 flex flex-col items-center justify-center gap-4 cursor-pointer ${dragOver ? "drag-over" : ""}`}
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={handleDrop}
                  onClick={() => inputRef.current?.click()}
                >
                  <input
                    ref={inputRef}
                    type="file"
                    className="hidden"
                    accept=".json,.xml,.har,.jsonl,.ndjson,.txt"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) uploadCapture(file);
                    }}
                  />
                  <div className="w-14 h-14 rounded border border-[rgba(99, 102, 241,0.25)] bg-[rgba(99, 102, 241,0.06)] flex items-center justify-center">
                    <Icon name="ArrowUpTrayIcon" size={26} className="text-[#6366F1]" />
                  </div>
                  <div className="text-center">
                    <p className="font-mono text-sm text-[#F8FAFC] font-semibold mb-1">
                      Drop traffic capture here
                    </p>
                    <p className="font-mono text-xs text-[#94A3B8]">
                      mitmproxy JSON · Burp Suite XML · HAR · JSONL · raw .txt
                    </p>
                  </div>
                  <div className="flex gap-2 flex-wrap justify-center">
                    {["mitmproxy", "Burp Suite", "HAR", "JSONL"].map((f) => (
                      <span key={f} className="font-mono text-[10px] px-2 py-0.5 rounded bg-[rgba(99, 102, 241,0.06)] text-[#94A3B8] border border-[rgba(99, 102, 241,0.1)] uppercase tracking-wider">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>

              </>
            )}

            {mode === "paste" && (
              <div className="space-y-4">
                <div>
                  <label className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest block mb-2">
                    Paste Raw HTTP Requests
                  </label>
                  <textarea
                    rows={14}
                    value={pasteText}
                    onChange={(e) => setPasteText(e.target.value)}
                    placeholder={`GET /api/users HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer token123\n\nPOST /api/login HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{"username":"test","password":"pass"}`}
                    className="w-full bg-[rgba(0,0,0,0.4)] border border-[rgba(99, 102, 241,0.12)] rounded px-3 py-2 font-mono text-xs text-[#F8FAFC] focus:outline-none focus:border-[rgba(99, 102, 241,0.4)] transition-colors resize-none"
                  />
                  <p className="font-mono text-[10px] text-[#475569] mt-1">
                    Paste one or more HTTP requests separated by blank lines. Each request block should start with a method line (GET /path HTTP/1.1).
                  </p>
                </div>
                <button
                  onClick={submitPaste}
                  disabled={!pasteText.trim()}
                  className={`w-full py-2.5 font-mono text-xs font-bold uppercase tracking-widest rounded transition-all ${pasteText.trim() ? "hacker-btn" : "bg-[rgba(99, 102, 241,0.05)] text-[#475569] cursor-not-allowed border border-[rgba(99, 102, 241,0.08)]"
                    }`}
                >
                  Parse & Ingest
                </button>
              </div>
            )}

            {error && (
              <div className="mt-4 font-mono text-[10px] text-[#FF4F4F]">
                {error}
              </div>
            )}
          </>
        ) : (
          <div className="py-8 space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-[#6366F1] animate-pulse" />
              <span className="font-mono text-xs text-[#6366F1] uppercase tracking-widest">{stage}</span>
            </div>
            <div className="h-1.5 bg-[rgba(99, 102, 241,0.08)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[#6366F1] rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="font-mono text-[10px] text-[#475569] text-right">{progress}%</div>
          </div>
        )}
      </div>
    </div>
  );
}
