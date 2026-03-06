"use client";

import { useEffect, useRef, useState } from "react";

const STATS = [
  { value: 34, suffix: "", label: "Endpoints / scan avg", sublabel: "auto-discovered" },
  { value: 2104, suffix: "+", label: "Fuzz cases generated", sublabel: "per typical session" },
  { value: 12, suffix: "", label: "Findings per scan avg", sublabel: "ranked by severity" },
  { value: 99.2, suffix: "%", label: "Schema accuracy", sublabel: "on observed traffic", decimal: true },
];

function Counter({ target, suffix, decimal }: { target: number; suffix: string; decimal?: boolean }) {
  const [val, setVal] = useState(0);
  const started = useRef(false);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && !started.current) {
          started.current = true;
          const duration = 1500;
          const start = performance.now();
          const animate = (now: number) => {
            const progress = Math.min((now - start) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            setVal(parseFloat((target * ease).toFixed(decimal ? 1 : 0)));
            if (progress < 1) requestAnimationFrame(animate);
          };
          requestAnimationFrame(animate);
        }
      },
      { threshold: 0.5 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target, decimal]);

  return (
    <span ref={ref}>
      {decimal ? val.toFixed(1) : Math.floor(val)}
      {suffix}
    </span>
  );
}

export default function StatsSection() {
  return (
    <section className="py-20 px-6 border-t border-[rgba(99, 102, 241,0.08)] bg-[rgba(99, 102, 241,0.02)]">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 md:gap-12">
          {STATS.map((stat, i) => (
            <div key={stat.label} className="relative">
              {i === 0 && (
                <div
                  className="absolute -top-6 left-0 w-3 h-3 bg-[#6366F1]"
                  style={{ boxShadow: "0 0 12px rgba(99, 102, 241,0.6)" }}
                />
              )}
              <div className="font-mono text-5xl md:text-7xl font-black text-[#6366F1] mb-2 leading-none">
                <Counter target={stat.value} suffix={stat.suffix} decimal={stat.decimal} />
              </div>
              <p className="font-mono text-xs text-[#94A3B8] uppercase tracking-widest border-t border-[rgba(99, 102, 241,0.08)] pt-3 mb-1">
                {stat.label}
              </p>
              <p className="font-mono text-[10px] text-[#475569] uppercase tracking-widest">
                {stat.sublabel}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}