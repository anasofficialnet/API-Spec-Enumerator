"use client";

import { useEffect, useRef } from "react";
import Icon from "@/components/ui/AppIcon";

const FEATURES = [
  {
    icon: "MagnifyingGlassIcon",
    title: "Schema Inference Engine",
    desc: "Automatically detects field types, optionality, enum values, and auth constraints from observed traffic patterns. No OpenAPI spec required.",
    size: "large",
    accent: "#00E676",
    detail: ["Type inference", "Enum detection", "Auth mapping", "Constraint learning"],
  },
  {
    icon: "BeakerIcon",
    title: "Intelligent Fuzz Generation",
    desc: "Generates targeted payloads per field type: SQLi, XSS, SSTI, path traversal, BOLA, and more.",
    size: "small",
    accent: "#FF4F4F",
    detail: ["2,100+ payload templates", "Context-aware"],
  },
  {
    icon: "ShieldCheckIcon",
    title: "Safe Replay Engine",
    desc: "Rate-limited request replay with configurable concurrency, auth header injection, and dry-run mode.",
    size: "small",
    accent: "#4FC3F7",
    detail: ["Rate: 1–100 req/s", "Auth passthrough"],
  },
  {
    icon: "ChartBarIcon",
    title: "Ranked Findings",
    desc: "Every finding is scored by severity (Critical → Info), deduplicated, and grouped by endpoint for fast triage.",
    size: "medium",
    accent: "#FF8C42",
    detail: ["CVSS-inspired scoring", "Dedup", "Endpoint grouping", "Evidence attached"],
  },
  {
    icon: "DocumentArrowDownIcon",
    title: "Export Reports",
    desc: "One-click HTML, JSON, and Markdown reports ready for your pentest deliverables.",
    size: "medium",
    accent: "#FFD166",
    detail: ["HTML", "JSON", "Markdown", "CSV"],
  },
];

export default function FeaturesBento() {
  const sectionRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.querySelectorAll(".bento-card").forEach((el, i) => {
              setTimeout(() => {
                (el as HTMLElement).style.opacity = "1";
                (el as HTMLElement).style.transform = "translateY(0)";
              }, i * 100);
            });
          }
        });
      },
      { threshold: 0.1 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section ref={sectionRef} className="py-24 px-6 border-t border-[rgba(0,230,118,0.08)]">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-xs text-[#00E676] tracking-[0.3em] uppercase">
            02 // CAPABILITIES
          </span>
          <div className="h-px flex-1 bg-[rgba(0,230,118,0.1)]" />
        </div>
        <h2 className="font-mono font-bold text-4xl md:text-5xl text-[#E8F5E9] leading-tight tracking-tighter uppercase mb-12">
          Built for <span className="text-[#00E676]">real pentesters.</span>
        </h2>

        {/* Bento grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Large feature */}
          <div
            className="bento-card md:col-span-2 terminal-window p-8 group hover:border-[rgba(0,230,118,0.3)] transition-all duration-500 cursor-default"
            style={{ opacity: 0, transform: "translateY(24px)", transition: "opacity 0.6s cubic-bezier(0.4,0,0.2,1), transform 0.6s cubic-bezier(0.4,0,0.2,1), border-color 0.3s" }}
          >
            <div className="flex items-start gap-4 mb-6">
              <div className="w-12 h-12 rounded border border-[rgba(0,230,118,0.25)] bg-[rgba(0,230,118,0.08)] flex items-center justify-center flex-shrink-0">
                <Icon name="MagnifyingGlassIcon" size={22} className="text-[#00E676]" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-xl text-[#E8F5E9] uppercase tracking-tight">Schema Inference Engine</h3>
                <p className="font-sans text-[#5A7A65] text-sm mt-1 leading-relaxed">
                  Automatically detects field types, optionality, enum values, and auth constraints from observed traffic patterns. No OpenAPI spec required.
                </p>
              </div>
            </div>
            {/* Schema visualization */}
            <div className="bg-[rgba(0,0,0,0.4)] rounded p-5 border border-[rgba(0,230,118,0.06)] font-mono text-xs space-y-1">
              <div className="text-[#5A7A65]">// inferred schema: POST /api/users</div>
              <div><span className="text-[#FFD166]">body</span><span className="text-[#5A7A65]">: {"{"}</span></div>
              <div className="pl-4"><span className="text-[#4FC3F7]">email</span><span className="text-[#5A7A65]">: </span><span className="text-[#FF8C42]">string(email)</span><span className="text-[#5A7A65]"> [required]</span></div>
              <div className="pl-4"><span className="text-[#4FC3F7]">role</span><span className="text-[#5A7A65]">: </span><span className="text-[#FF8C42]">enum</span><span className="text-[#5A7A65]">[</span><span className="text-[#00E676]">"admin","user","viewer"</span><span className="text-[#5A7A65]">]</span></div>
              <div className="pl-4"><span className="text-[#4FC3F7]">age</span><span className="text-[#5A7A65]">: </span><span className="text-[#FF8C42]">integer</span><span className="text-[#5A7A65]"> [min:18, max:120]</span></div>
              <div className="text-[#5A7A65]">{"}"}</div>
              <div className="pt-2 flex gap-4">
                {["Type inference", "Enum detection", "Auth mapping", "Constraint learning"].map((tag) => (
                  <span key={tag} className="px-2 py-0.5 rounded bg-[rgba(0,230,118,0.08)] text-[#00E676] border border-[rgba(0,230,118,0.15)] text-[10px] uppercase tracking-wider">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Small: Fuzz */}
          <div
            className="bento-card terminal-window p-7 group hover:border-[rgba(255,79,79,0.3)] transition-all duration-500 cursor-default"
            style={{ opacity: 0, transform: "translateY(24px)", transition: "opacity 0.6s 0.1s cubic-bezier(0.4,0,0.2,1), transform 0.6s 0.1s cubic-bezier(0.4,0,0.2,1), border-color 0.3s" }}
          >
            <div className="w-10 h-10 rounded border border-[rgba(255,79,79,0.25)] bg-[rgba(255,79,79,0.08)] flex items-center justify-center mb-5">
              <Icon name="BeakerIcon" size={20} className="text-[#FF4F4F]" />
            </div>
            <h3 className="font-mono font-bold text-lg text-[#E8F5E9] uppercase tracking-tight mb-2">Fuzz Generation</h3>
            <p className="font-sans text-[#5A7A65] text-sm leading-relaxed mb-5">
              Generates targeted payloads per field type: SQLi, XSS, SSTI, path traversal, BOLA, and more.
            </p>
            <div className="space-y-1.5">
              {["SQLi payloads", "XSS vectors", "BOLA probes", "Path traversal"].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-[#FF4F4F]" />
                  <span className="font-mono text-[11px] text-[#5A7A65]">{item}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Small: Safe Replay */}
          <div
            className="bento-card terminal-window p-7 group hover:border-[rgba(79,195,247,0.3)] transition-all duration-500 cursor-default"
            style={{ opacity: 0, transform: "translateY(24px)", transition: "opacity 0.6s 0.2s cubic-bezier(0.4,0,0.2,1), transform 0.6s 0.2s cubic-bezier(0.4,0,0.2,1), border-color 0.3s" }}
          >
            <div className="w-10 h-10 rounded border border-[rgba(79,195,247,0.25)] bg-[rgba(79,195,247,0.08)] flex items-center justify-center mb-5">
              <Icon name="ShieldCheckIcon" size={20} className="text-[#4FC3F7]" />
            </div>
            <h3 className="font-mono font-bold text-lg text-[#E8F5E9] uppercase tracking-tight mb-2">Safe Replay</h3>
            <p className="font-sans text-[#5A7A65] text-sm leading-relaxed mb-4">
              Rate-limited request replay with configurable concurrency and auth header injection.
            </p>
            <div className="font-mono text-xs bg-[rgba(0,0,0,0.4)] rounded p-3 border border-[rgba(0,230,118,0.06)]">
              <div className="text-[#4FC3F7]">--rate <span className="text-[#00E676]">10</span>/s</div>
              <div className="text-[#4FC3F7]">--concurrency <span className="text-[#00E676]">3</span></div>
              <div className="text-[#4FC3F7]">--dry-run <span className="text-[#FFD166]">false</span></div>
            </div>
          </div>

          {/* Medium: Ranked Findings */}
          <div
            className="bento-card md:col-span-2 terminal-window p-7 group hover:border-[rgba(255,140,66,0.3)] transition-all duration-500 cursor-default"
            style={{ opacity: 0, transform: "translateY(24px)", transition: "opacity 0.6s 0.3s cubic-bezier(0.4,0,0.2,1), transform 0.6s 0.3s cubic-bezier(0.4,0,0.2,1), border-color 0.3s" }}
          >
            <div className="flex items-start gap-4 mb-5">
              <div className="w-10 h-10 rounded border border-[rgba(255,140,66,0.25)] bg-[rgba(255,140,66,0.08)] flex items-center justify-center flex-shrink-0">
                <Icon name="ChartBarIcon" size={20} className="text-[#FF8C42]" />
              </div>
              <div>
                <h3 className="font-mono font-bold text-lg text-[#E8F5E9] uppercase tracking-tight">Ranked Findings</h3>
                <p className="font-sans text-[#5A7A65] text-sm mt-1">CVSS-inspired scoring, deduplicated, grouped by endpoint.</p>
              </div>
            </div>
            <div className="space-y-2">
              {[
                { sev: "CRITICAL", label: "SQL Injection", ep: "/api/users?id=", pct: 95 },
                { sev: "HIGH", label: "BOLA / IDOR", ep: "/api/orders/{id}", pct: 78 },
                { sev: "MEDIUM", label: "Missing Rate Limit", ep: "/api/auth/login", pct: 52 },
                { sev: "LOW", label: "Verbose Error", ep: "/api/internal/debug", pct: 28 },
              ].map((f) => (
                <div key={f.label} className="flex items-center gap-3">
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase tracking-wider flex-shrink-0 ${
                      f.sev === "CRITICAL" ? "badge-critical" : f.sev === "HIGH" ? "badge-high" : f.sev === "MEDIUM" ? "badge-medium" : "badge-low"
                    }`}
                  >
                    {f.sev}
                  </span>
                  <span className="font-mono text-xs text-[#E8F5E9] flex-shrink-0 w-36 truncate">{f.label}</span>
                  <div className="flex-1 h-1.5 bg-[rgba(0,230,118,0.06)] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${f.pct}%`,
                        background: f.sev === "CRITICAL" ? "#FF4F4F" : f.sev === "HIGH" ? "#FF8C42" : f.sev === "MEDIUM" ? "#FFD166" : "#00E676",
                      }}
                    />
                  </div>
                  <span className="font-mono text-[10px] text-[#2E4A38] w-8 text-right">{f.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}