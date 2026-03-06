import Link from "next/link";
import Icon from "@/components/ui/AppIcon";

export default function CtaSection() {
  return (
    <section className="py-28 px-6 border-t border-[rgba(99, 102, 241,0.08)] relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: "radial-gradient(ellipse 60% 50% at 50% 100%, rgba(99, 102, 241,0.06) 0%, transparent 70%)",
        }}
      />
      <div className="max-w-4xl mx-auto text-center relative z-10">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 mb-8 font-mono text-xs text-[#6366F1] bg-[rgba(99, 102, 241,0.08)] border border-[rgba(99, 102, 241,0.2)] rounded-full">
          <Icon name="CommandLineIcon" size={14} />
          READY TO SCAN YOUR API?
        </div>
        <h2 className="font-mono font-black text-4xl md:text-6xl text-[#F8FAFC] leading-tight tracking-tighter uppercase mb-6">
          Stop guessing.<br />
          <span className="text-[#6366F1] text-glow">Start finding.</span>
        </h2>
        <p className="font-sans text-[#94A3B8] text-lg max-w-xl mx-auto mb-12 leading-relaxed">
          Upload your first traffic capture and get a full vulnerability report in under 60 seconds.
          No config. No spec. Just results.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            href="/dashboard"
            className="hacker-btn inline-flex items-center gap-2 justify-center text-sm py-4 px-10"
          >
            <Icon name="RocketLaunchIcon" size={16} />
            Open Dashboard
          </Link>
        </div>

        {/* Terminal one-liner */}
        <div className="mt-12 inline-block terminal-window px-6 py-3">
          <code className="font-mono text-xs text-[#94A3B8]">
            $ <span className="text-[#6366F1]">aase</span> ingest dump.json --target https://api.yourapp.dev --fuzz
          </code>
        </div>
      </div>
    </section>
  );
}