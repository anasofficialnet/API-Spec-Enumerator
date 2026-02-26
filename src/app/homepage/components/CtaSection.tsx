import Link from "next/link";
import Icon from "@/components/ui/AppIcon";

export default function CtaSection() {
  return (
    <section className="py-28 px-6 border-t border-[rgba(0,230,118,0.08)] relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: "radial-gradient(ellipse 60% 50% at 50% 100%, rgba(0,230,118,0.06) 0%, transparent 70%)",
        }}
      />
      <div className="max-w-4xl mx-auto text-center relative z-10">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 mb-8 font-mono text-xs text-[#00E676] bg-[rgba(0,230,118,0.08)] border border-[rgba(0,230,118,0.2)] rounded-full">
          <Icon name="CommandLineIcon" size={14} />
          READY TO SCAN YOUR API?
        </div>
        <h2 className="font-mono font-black text-4xl md:text-6xl text-[#E8F5E9] leading-tight tracking-tighter uppercase mb-6">
          Stop guessing.<br />
          <span className="text-[#00E676] text-glow">Start finding.</span>
        </h2>
        <p className="font-sans text-[#5A7A65] text-lg max-w-xl mx-auto mb-12 leading-relaxed">
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
          <Link
            href="/reports"
            className="inline-flex items-center gap-2 justify-center px-10 py-4 font-mono text-sm text-[#5A7A65] border border-[rgba(0,230,118,0.12)] rounded hover:text-[#00E676] hover:border-[rgba(0,230,118,0.3)] transition-all"
          >
            <Icon name="EyeIcon" size={16} />
            View Demo Report
          </Link>
        </div>

        {/* Terminal one-liner */}
        <div className="mt-12 inline-block terminal-window px-6 py-3">
          <code className="font-mono text-xs text-[#5A7A65]">
            $ <span className="text-[#00E676]">aase</span> ingest dump.json --target https://api.yourapp.dev --fuzz
          </code>
        </div>
      </div>
    </section>
  );
}