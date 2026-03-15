"use client";

import Link from "next/link";

import Icon from "@/components/ui/AppIcon";

export default function HeroSection() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden pt-24 pb-16 px-6">
      <div className="relative z-10 max-w-4xl w-full text-center">
        <div className="fade-up inline-flex items-center gap-2 px-4 py-1.5 mb-8 font-mono text-xs text-[#6366F1] bg-[rgba(99, 102, 241,0.08)] border border-[rgba(255,255,255,0.08)] rounded-full backdrop-blur-xl">
          <span className="w-1.5 h-1.5 rounded-full bg-[#6366F1] animate-pulse" />
          ADAPTIVE API SPEC ENUMERATOR - v2.4.1
        </div>

        <div className="fade-up stagger-1">
          <h1 className="font-mono font-black text-[clamp(2.2rem,7vw,5.5rem)] leading-[0.9] tracking-tighter mb-6">
            <span className="block text-[#F8FAFC]">UPLOAD TRAFFIC.</span>
            <span className="block text-[#6366F1] text-glow">FIND VULNS.</span>
            <span className="block text-[#F8FAFC]">SHIP FIXES.</span>
          </h1>

          <p className="font-sans text-[#94A3B8] text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed">
            AASE ingests your mitmproxy or Burp Suite captures, infers API schemas automatically,
            generates intelligent fuzz cases, and reports live findings from real responses without manual spec writing.
          </p>
        </div>

        <div className="fade-up stagger-2 flex flex-col sm:flex-row gap-4 justify-center mb-16">
          <Link
            href="/dashboard"
            className="btn btn-primary font-mono text-sm uppercase tracking-[0.08em] px-8"
          >
            <Icon name="RocketLaunchIcon" size={16} />
            Launch Dashboard
          </Link>
        </div>
      </div>

    </section>
  );
}
