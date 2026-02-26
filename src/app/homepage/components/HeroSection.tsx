"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import Icon from "@/components/ui/AppIcon";

const TERMINAL_LINES = [
  { text: "$ aase init --source mitmproxy_dump.json", color: "#00E676", delay: 0 },
  { text: "[+] Parsing 1,847 HTTP transactions...", color: "#5A7A65", delay: 600 },
  { text: "[+] Discovered 34 unique endpoints", color: "#5A7A65", delay: 1200 },
  { text: "[+] Inferring schemas... done (34/34)", color: "#5A7A65", delay: 1800 },
  { text: "[+] Generating fuzz cases: 2,104 total", color: "#5A7A65", delay: 2400 },
  { text: "$ aase fuzz --target https://api.target.dev --rate 10/s", color: "#00E676", delay: 3200 },
  { text: "[!] CRITICAL: SQL injection — /api/users?id=", color: "#FF4F4F", delay: 4000 },
  { text: "[!] HIGH: BOLA — /api/orders/{id} (unauth read)", color: "#FF8C42", delay: 4600 },
  { text: "[+] Scan complete. 12 findings. Report saved.", color: "#00E676", delay: 5200 },
];

export default function HeroSection() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [typedIndex, setTypedIndex] = useState(0);

  // Matrix / network particle canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%&*><{}[]";
    const fontSize = 12;
    let cols = Math.floor(canvas.width / fontSize);
    const drops: number[] = Array(cols).fill(1);

    function draw() {
      ctx!.fillStyle = "rgba(8, 12, 10, 0.05)";
      ctx!.fillRect(0, 0, canvas!.width, canvas!.height);
      ctx!.fillStyle = "rgba(0, 230, 118, 0.18)";
      ctx!.font = `${fontSize}px monospace`;
      cols = Math.floor(canvas!.width / fontSize);
      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx!.fillText(char, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > canvas!.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
      animId = requestAnimationFrame(draw);
    }
    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  // Terminal typing effect
  useEffect(() => {
    TERMINAL_LINES.forEach((line, i) => {
      const timer = setTimeout(() => {
        setVisibleLines((prev) => [...prev, i]);
      }, line.delay);
      return () => clearTimeout(timer);
    });
  }, []);

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden pt-24 pb-16 px-6">
      {/* Matrix rain bg */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full opacity-30 pointer-events-none"
        style={{ zIndex: 0 }}
      />

      {/* Grid overlay */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,230,118,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,230,118,0.025) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          zIndex: 1,
        }}
      />

      {/* Radial glow center */}
      <div
        className="absolute pointer-events-none"
        style={{
          top: "40%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          width: "600px",
          height: "600px",
          background: "radial-gradient(circle, rgba(0,230,118,0.06) 0%, transparent 70%)",
          zIndex: 1,
        }}
      />

      {/* Content */}
      <div className="relative z-10 max-w-5xl w-full text-center">
        {/* Status badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 mb-8 font-mono text-xs text-[#00E676] bg-[rgba(0,230,118,0.08)] border border-[rgba(0,230,118,0.2)] rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00E676] animate-pulse" />
          ADAPTIVE API SPEC ENUMERATOR — v2.4.1
        </div>

        {/* Main headline */}
        <h1 className="font-mono font-black text-[clamp(2.2rem,7vw,5.5rem)] leading-[0.9] tracking-tighter mb-6">
          <span className="block text-[#E8F5E9]">UPLOAD TRAFFIC.</span>
          <span className="block text-[#00E676] text-glow">FIND VULNS.</span>
          <span className="block text-[#E8F5E9]">SHIP FIXES.</span>
        </h1>

        <p className="font-sans text-[#5A7A65] text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed">
          AASE ingests your mitmproxy or Burp Suite captures, infers API schemas automatically,
          generates intelligent fuzz cases, and reports real vulnerabilities — no manual spec writing.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
          <Link href="/dashboard" className="hacker-btn text-sm py-3 px-8 inline-flex items-center gap-2 justify-center">
            <Icon name="RocketLaunchIcon" size={16} />
            Launch Dashboard
          </Link>
          <Link
            href="/reports"
            className="inline-flex items-center gap-2 justify-center px-8 py-3 font-mono text-sm text-[#5A7A65] border border-[rgba(0,230,118,0.12)] rounded hover:text-[#00E676] hover:border-[rgba(0,230,118,0.3)] transition-all"
          >
            <Icon name="DocumentTextIcon" size={16} />
            View Sample Report
          </Link>
        </div>

        {/* Terminal mockup */}
        <div className="terminal-window max-w-3xl mx-auto text-left float-anim">
          <div className="terminal-header">
            <div className="terminal-dot" style={{ background: "#FF5F56" }} />
            <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
            <div className="terminal-dot" style={{ background: "#27C93F" }} />
            <span className="font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest ml-3">
              aase_terminal — bash
            </span>
          </div>
          <div className="p-6 min-h-[260px] font-mono text-xs space-y-2 bg-[rgba(0,0,0,0.3)]">
            {TERMINAL_LINES.map((line, i) =>
              visibleLines.includes(i) ? (
                <div key={i} style={{ color: line.color }} className="fade-in-up">
                  {line.text}
                </div>
              ) : null
            )}
            {visibleLines.length < TERMINAL_LINES.length && (
              <span className="inline-block w-2 h-4 bg-[#00E676] cursor-blink" />
            )}
          </div>
        </div>
      </div>

      {/* Scroll indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10 flex flex-col items-center gap-2 font-mono text-[10px] text-[#2E4A38] uppercase tracking-widest animate-bounce">
        <Icon name="ChevronDownIcon" size={16} className="text-[#2E4A38]" />
        scroll_to_explore
      </div>
    </section>
  );
}