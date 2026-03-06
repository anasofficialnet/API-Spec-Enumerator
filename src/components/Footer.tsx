import Link from "next/link";

export default function Footer() {
  return (
    <footer className="border-t border-[rgba(255,255,255,0.08)] bg-[rgba(7,12,20,0.42)] backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-6 py-8 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-6">
          <span className="font-mono text-[#475569] text-xs">
            © 2026 AASE Security Systems
          </span>
          <Link
            href="/"
            className="font-mono text-[#475569] text-xs hover:text-[#6366F1] transition-colors"
          >
            Home
          </Link>
          <Link
            href="/dashboard"
            className="font-mono text-[#475569] text-xs hover:text-[#6366F1] transition-colors"
          >
            Dashboard
          </Link>
          <Link
            href="/reports"
            className="font-mono text-[#475569] text-xs hover:text-[#6366F1] transition-colors"
          >
            Reports
          </Link>
        </div>
        <div className="flex items-center gap-4">
          <span className="font-mono text-[#475569] text-xs">
            Privacy · Terms
          </span>
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-[#475569] uppercase tracking-widest">
            <span className="w-1.5 h-1.5 rounded-full bg-[#6366F1] opacity-60" />
            Offline-capable
          </div>
        </div>
      </div>
    </footer>
  );
}
