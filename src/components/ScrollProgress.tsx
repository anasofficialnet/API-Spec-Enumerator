"use client";

import { useEffect, useRef } from "react";

export default function ScrollProgress() {
  const barRef = useRef<HTMLDivElement | null>(null);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    const element = barRef.current;
    if (!element) {
      return;
    }

    const update = () => {
      frameRef.current = null;

      const doc = document.documentElement;
      const scrollTop = doc.scrollTop || document.body.scrollTop;
      const maxScroll =
        (doc.scrollHeight || document.body.scrollHeight) - doc.clientHeight;
      const progress = maxScroll > 0 ? scrollTop / maxScroll : 0;

      element.style.transform = `scaleX(${progress})`;
    };

    const onScroll = () => {
      if (frameRef.current !== null) {
        return;
      }

      frameRef.current = window.requestAnimationFrame(update);
    };

    update();
    window.addEventListener("scroll", onScroll, { passive: true });

    return () => {
      window.removeEventListener("scroll", onScroll);
      if (frameRef.current !== null) {
        window.cancelAnimationFrame(frameRef.current);
      }
    };
  }, []);

  return <div ref={barRef} className="scroll-progress" />;
}
