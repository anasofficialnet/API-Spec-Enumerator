"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import Icon from "@/components/ui/AppIcon";

const navLinks = [
  { label: "Home", href: "/homepage" },
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
      className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${
        scrolled
          ? "bg-[#080C0A]/95 backdrop-blur-md border-b border-[rgba(0,230,118,0.12)]"
          : "bg-transparent"
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <Link href="/homepage" className="flex items-center gap-3 group">
          <div className="w-8 h-8 bg-[rgba(0,230,118,0.1)] border border-[rgba(0,230,118,0.3)] rounded flex items-center justify-center">
            <span className="font-mono text-[#00E676] text-xs font-bold">A</span>
          </div>
          <span className="font-mono text-[#00E676] font-bold text-lg tracking-tight">
            AASE<span className="animate-blink text-[#00E676]">_</span>
          </span>
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks?.map((link) => {
            const isActive = pathname === link?.href;
            return (
              <Link
                key={link?.href}
                href={link?.href}
                className={`font-mono text-xs px-4 py-2 rounded transition-all duration-200 tracking-widest uppercase font-semibold ${
                  isActive
                    ? "text-[#00E676] bg-[rgba(0,230,118,0.1)] border border-[rgba(0,230,118,0.2)]"
                    : "text-[#5A7A65] hover:text-[#00E676] hover:bg-[rgba(0,230,118,0.05)]"
                }`}
              >
                {link?.label}
              </Link>
            );
          })}
        </nav>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono text-[10px] text-[#5A7A65] uppercase tracking-widest">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00E676] animate-pulse" />
            v2.4.1 live
          </div>
          <Link
            href="/dashboard"
            className="hacker-btn text-xs py-2 px-5"
          >
            Launch Dashboard
          </Link>
        </div>

        {/* Mobile toggle */}
        <button
          className="md:hidden text-[#5A7A65] hover:text-[#00E676] transition-colors p-2"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          <Icon name={mobileOpen ? "XMarkIcon" : "Bars3Icon"} size={22} />
        </button>
      </div>
      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden bg-[#0D1410] border-t border-[rgba(0,230,118,0.12)] px-6 py-4 flex flex-col gap-2">
          {navLinks?.map((link) => {
            const isActive = pathname === link?.href;
            return (
              <Link
                key={link?.href}
                href={link?.href}
                onClick={() => setMobileOpen(false)}
                className={`font-mono text-xs px-4 py-3 rounded transition-all uppercase tracking-widest font-semibold ${
                  isActive
                    ? "text-[#00E676] bg-[rgba(0,230,118,0.1)]"
                    : "text-[#5A7A65] hover:text-[#00E676]"
                }`}
              >
                {link?.label}
              </Link>
            );
          })}
          <Link
            href="/dashboard"
            onClick={() => setMobileOpen(false)}
            className="hacker-btn text-xs py-3 text-center mt-2"
          >
            Launch Dashboard
          </Link>
        </div>
      )}
    </header>
  );
}