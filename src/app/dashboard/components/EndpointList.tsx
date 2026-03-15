"use client";

import { useState } from "react";
import type { EndpointData } from "./UploadPanel";
import Icon from "@/components/ui/AppIcon";
import HelpTooltip from "./HelpTooltip";
import { compareEndpointsBySource, getEndpointSourcePresentation } from "./endpointSource.js";

interface EndpointListProps {
  endpoints: EndpointData[];
  caseCountOverrides?: Record<string, number>;
  selected: string[];
  onSelectionChange: (ids: string[]) => void;
}

const METHOD_CLASS: Record<string, string> = {
  GET: "method-get",
  POST: "method-post",
  PUT: "method-put",
  DELETE: "method-delete",
  PATCH: "method-patch",
};

const INVENTORY_COLUMN_HELP = {
  summary: "Auth shows whether the scanner saw login headers or cookies on that endpoint. Conf. shows how much of the request shape we could understand. Cases shows how many requests the scanner will build for that endpoint.",
  when: "Use this row to decide which endpoints look real, how reliable the shape is, and how large the scan will be.",
};

export default function EndpointList({ endpoints, caseCountOverrides = {}, selected, onSelectionChange }: EndpointListProps) {
  const [filter, setFilter] = useState("ALL");

  const methods = ["ALL", "GET", "POST", "PUT", "DELETE", "PATCH"];
  const filtered = (filter === "ALL" ? endpoints : endpoints.filter((e) => e.method === filter))
    .slice()
    .sort(compareEndpointsBySource);

  const toggleAll = () => {
    if (selected.length === filtered.length) {
      onSelectionChange([]);
    } else {
      onSelectionChange(filtered.map((e) => e.id));
    }
  };

  const toggle = (id: string) => {
    onSelectionChange(
      selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id]
    );
  };

  const getCaseCount = (endpoint: EndpointData) => caseCountOverrides[endpoint.id] ?? endpoint.fuzzCases;

  return (
    <div className="terminal-window flex flex-col h-full">
      <div className="terminal-header justify-between">
        <div className="flex items-center gap-2">
          <div className="terminal-dot" style={{ background: "#FF5F56" }} />
          <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
          <div className="terminal-dot" style={{ background: "#27C93F" }} />
          <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest ml-2">
            endpoints ({endpoints.length})
          </span>
        </div>
        <div className="flex gap-1">
          {methods.map((m) => (
            <button
              key={m}
              onClick={() => setFilter(m)}
              className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider transition-all ${
                filter === m
                  ? "bg-[rgba(99, 102, 241,0.15)] text-[#6366F1] border border-[rgba(99, 102, 241,0.3)]"
                  : "text-[#475569] hover:text-[#94A3B8]"
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {/* Header row */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[rgba(99, 102, 241,0.06)] bg-[rgba(99, 102, 241,0.02)]">
        <input
          type="checkbox"
          checked={selected.length === filtered.length && filtered.length > 0}
          onChange={toggleAll}
          className="w-3.5 h-3.5 accent-[#6366F1] cursor-pointer"
        />
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest flex-1">Endpoint</span>
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest w-32 text-left">Source</span>
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest w-16 text-center">Auth</span>
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest w-16 text-center">Conf.</span>
        <div className="flex w-20 items-center justify-center gap-1">
          <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">Cases</span>
          <HelpTooltip summary={INVENTORY_COLUMN_HELP.summary} when={INVENTORY_COLUMN_HELP.when} />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {filtered.map((ep) => {
          const source = getEndpointSourcePresentation(ep);
          return (
            <div
              key={ep.id}
              className={`endpoint-row flex items-center gap-3 px-4 py-3 border-b border-[rgba(99, 102, 241,0.04)] cursor-pointer ${
                selected.includes(ep.id) ? "bg-[rgba(99, 102, 241,0.04)]" : ""
              }`}
              onClick={() => toggle(ep.id)}
            >
              <input
                type="checkbox"
                checked={selected.includes(ep.id)}
                onChange={() => toggle(ep.id)}
                onClick={(e) => e.stopPropagation()}
                className="w-3.5 h-3.5 accent-[#6366F1] cursor-pointer flex-shrink-0"
              />
              <span
                className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider flex-shrink-0 ${METHOD_CLASS[ep.method] || "method-get"}`}
              >
                {ep.method}
              </span>
              <div className="flex-1 min-w-0">
                <div className="font-mono text-xs text-[#F8FAFC] truncate">{ep.path}</div>
                <div className="font-mono text-[10px] text-[#475569] truncate">{ep.host}</div>
              </div>
              <div className="w-32 text-left" title={source.tooltip}>
                <div className="font-mono text-[10px] text-[#A78BFA] truncate uppercase tracking-wider">{source.label}</div>
                {source.statusLabel ? (
                  <div className="font-mono text-[9px] text-[#475569] uppercase tracking-wider mt-0.5">
                    {source.statusLabel}
                  </div>
                ) : (
                  <div className="h-[14px]" />
                )}
              </div>
              <div className="w-16 text-center">
                {ep.authRequired ? (
                  <Icon name="LockClosedIcon" size={14} className="text-[#FFD166] mx-auto" />
                ) : (
                  <Icon name="LockOpenIcon" size={14} className="text-[#475569] mx-auto" />
                )}
              </div>
              <div className="w-16 text-center">
                <span
                  className={`font-mono text-xs ${
                    ep.schemaConfidence >= 90 ? "text-[#6366F1]" : ep.schemaConfidence >= 75 ? "text-[#FFD166]" : "text-[#FF8C42]"
                  }`}
                >
                  {ep.schemaConfidence}%
                </span>
              </div>
              <div className="w-20 text-center">
                <span className="font-mono text-xs text-[#94A3B8]">{getCaseCount(ep)}</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="px-4 py-3 border-t border-[rgba(99, 102, 241,0.08)] flex items-center justify-between">
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">
          {selected.length} / {filtered.length} selected
        </span>
        <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">
          {filtered.reduce((sum, endpoint) => sum + getCaseCount(endpoint), 0)} total cases
        </span>
      </div>
    </div>
  );
}
