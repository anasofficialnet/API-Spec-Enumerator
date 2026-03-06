"use client";

import Icon from "@/components/ui/AppIcon";

const STEPS = [
  {
    num: "01",
    icon: "ArrowUpTrayIcon",
    title: "Ingest Traffic",
    subtitle: "mitmproxy · Burp Suite",
    desc: "Upload your captured HTTP traffic as JSON or XML. AASE parses every request and response, extracting endpoints, parameters, headers, and body schemas.",
    code: `$ aase ingest dump.json
[+] Format: mitmproxy JSON
[+] Transactions: 1,847
[+] Unique hosts: 3`,
    color: "#4FC3F7",
  },
  {
    num: "02",
    icon: "CpuChipIcon",
    title: "Infer Schema",
    subtitle: "Automatic · Hypothesis-based",
    desc: "AASE analyzes request/response patterns to infer field types, constraints, auth requirements, and access control rules without any manual OpenAPI spec.",
    code: `[+] Endpoints: 34 discovered
[+] Auth required: 28/34
[+] Schema confidence: 94%
[+] IDOR candidates: 7`,
    color: "#6366F1",
  },
  {
    num: "03",
    icon: "BoltIcon",
    title: "Fuzz & Report",
    subtitle: "Rate-limited · Safe",
    desc: "Intelligently generated fuzz cases replay against your target at a safe rate with your auth tokens. Findings are ranked by severity and exported as a report.",
    code: `[!] CRITICAL: SQLi /users?id=
[!] HIGH: BOLA /orders/{id}
[+] 2,104 cases. 12 findings.
[+] Report: report_2026.html`,
    color: "#FF8C42",
  },
];

export default function HowItWorks() {
  return (
    <section className="py-24 px-6 border-t border-[rgba(99, 102, 241,0.08)] relative">
      {/* Section label */}
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-xs text-[#6366F1] tracking-[0.3em] uppercase">
            01 // HOW_IT_WORKS
          </span>
          <div className="h-px flex-1 bg-[rgba(99, 102, 241,0.1)]" />
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-16">
          <h2 className="font-mono font-bold text-4xl md:text-6xl text-[#F8FAFC] leading-tight tracking-tighter uppercase">
            Three steps.<br />
            <span className="text-[#6366F1]">Zero guesswork.</span>
          </h2>
          <p className="font-sans text-[#94A3B8] max-w-sm text-base leading-relaxed">
            From raw traffic dump to a ranked vulnerability report in under 60 seconds on a modern laptop.
          </p>
        </div>

        {/* Steps */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {STEPS.map((step, i) => (
            <div
              key={step.num}
              className={`fade-up terminal-window p-8 flex flex-col gap-6 group hover:border-[rgba(99, 102, 241,0.3)] transition-all duration-500 stagger-${
                i + 1
              }`}
              style={{
                borderColor: "rgba(99, 102, 241,0.12)",
              }}
            >
              {/* Number + icon */}
              <div className="flex items-start justify-between">
                <div
                  className="w-12 h-12 rounded border flex items-center justify-center"
                  style={{
                    background: `rgba(${step.color === "#4FC3F7" ? "79,195,247" : step.color === "#6366F1" ? "99, 102, 241" : "255,140,66"},0.08)`,
                    borderColor: `rgba(${step.color === "#4FC3F7" ? "79,195,247" : step.color === "#6366F1" ? "99, 102, 241" : "255,140,66"},0.25)`,
                  }}
                >
                  <Icon name={step.icon as any} size={22} className="" style={{ color: step.color }} />
                </div>
                <span className="font-mono text-4xl font-black text-[#475569]">{step.num}</span>
              </div>

              {/* Title */}
              <div>
                <h3 className="font-mono font-bold text-xl text-[#F8FAFC] uppercase tracking-tight mb-1">
                  {step.title}
                </h3>
                <span
                  className="font-mono text-xs tracking-widest uppercase"
                  style={{ color: step.color }}
                >
                  {step.subtitle}
                </span>
              </div>

              {/* Desc */}
              <p className="font-sans text-[#94A3B8] text-sm leading-relaxed flex-1">
                {step.desc}
              </p>

              {/* Code snippet */}
              <div className="bg-[rgba(0,0,0,0.4)] rounded p-4 border border-[rgba(99, 102, 241,0.06)]">
                <pre className="font-mono text-[11px] text-[#94A3B8] whitespace-pre-wrap leading-relaxed">
                  {step.code}
                </pre>
              </div>

              {/* Bottom indicator */}
              <div className="flex justify-between items-center border-t border-[rgba(99, 102, 241,0.08)] pt-4">
                <span className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">
                  STEP_{step.num}
                </span>
                <div
                  className="w-2 h-2 rounded-full group-hover:scale-150 transition-transform"
                  style={{ background: step.color }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
