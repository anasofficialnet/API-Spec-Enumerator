"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import dynamic from "next/dynamic";

const Icon = dynamic(() => import("@/components/ui/AppIcon"), {
  ssr: false,
});

const navLinks = [
  { label: "Home", href: "/" },
  { label: "Dashboard", href: "/dashboard" },
  { label: "Reports", href: "/reports" },
];

export default function Header() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${scrolled
          ? "chrome-bar border-b"
          : "bg-transparent"
        }`}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-end gap-4">
        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-1 mr-auto">
          {navLinks?.map((link) => {
            const isActive = pathname === link?.href;
            return (
              <Link
                key={link?.href}
                href={link?.href}
                className={`nav-pill font-mono text-xs tracking-widest uppercase font-semibold ${isActive
                    ? "nav-pill-active"
                    : ""
                  }`}
              >
                {link?.label}
              </Link>
            );
          })}
        </nav>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono text-[10px] text-[#94A3B8] uppercase tracking-widest">
            <span className="w-1.5 h-1.5 rounded-full bg-[#6366F1] animate-pulse" />
            v2.4.1 live
          </div>
          <Link
            href="/dashboard"
            className="btn btn-primary font-mono text-xs uppercase tracking-[0.08em]"
          >
            Launch Dashboard
          </Link>
        </div>

        {/* Mobile toggle */}
        <button
          className="md:hidden ml-auto text-[#94A3B8] hover:text-[#6366F1] transition-colors p-2"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          <Icon name={mobileOpen ? "XMarkIcon" : "Bars3Icon"} size={22} />
        </button>
      </div>
      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden mx-4 mb-4 rounded-3xl border border-[rgba(255,255,255,0.08)] bg-[rgba(7,12,20,0.68)] backdrop-blur-xl px-4 py-4 flex flex-col gap-2">
          {navLinks?.map((link) => {
            const isActive = pathname === link?.href;
            return (
              <Link
                key={link?.href}
                href={link?.href}
                onClick={() => setMobileOpen(false)}
                className={`nav-pill justify-start font-mono text-xs px-4 py-3 uppercase tracking-widest font-semibold ${isActive
                    ? "nav-pill-active"
                    : ""
                  }`}
              >
                {link?.label}
              </Link>
            );
          })}
          <Link
            href="/dashboard"
            onClick={() => setMobileOpen(false)}
            className="btn btn-primary font-mono text-xs uppercase tracking-[0.08em] text-center mt-2"
          >
            Launch Dashboard
          </Link>
        </div>
      )}
    </header>
  );
}
