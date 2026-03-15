"use client";

import React from "react";
import { createPortal } from "react-dom";

interface HelpTooltipProps {
  summary: string;
  requires?: string | null;
  when?: string | null;
  triggerClassName?: string;
}

const TOOLTIP_MARGIN = 12;
const TOOLTIP_WIDTH = 288;

function estimateTooltipHeight(requires?: string | null, when?: string | null) {
  let height = 56;
  if (requires) {
    height += 28;
  }
  if (when) {
    height += 28;
  }
  return height;
}

export default function HelpTooltip({
  summary,
  requires,
  when,
  triggerClassName,
}: HelpTooltipProps) {
  const triggerRef = React.useRef<HTMLSpanElement | null>(null);
  const [isOpen, setIsOpen] = React.useState(false);
  const [tooltipStyle, setTooltipStyle] = React.useState<React.CSSProperties | null>(null);

  const updatePosition = React.useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger || typeof window === "undefined") {
      return;
    }

    const rect = trigger.getBoundingClientRect();
    const width = Math.min(TOOLTIP_WIDTH, window.innerWidth - (TOOLTIP_MARGIN * 2));
    const estimatedHeight = estimateTooltipHeight(requires, when);
    const spaceBelow = window.innerHeight - rect.bottom;
    const placeAbove = spaceBelow < estimatedHeight + TOOLTIP_MARGIN && rect.top > estimatedHeight + TOOLTIP_MARGIN;

    let left = rect.left + (rect.width / 2) - (width / 2);
    left = Math.max(TOOLTIP_MARGIN, Math.min(left, window.innerWidth - width - TOOLTIP_MARGIN));

    let top = placeAbove ? rect.top - estimatedHeight - 10 : rect.bottom + 10;
    top = Math.max(TOOLTIP_MARGIN, Math.min(top, window.innerHeight - estimatedHeight - TOOLTIP_MARGIN));

    setTooltipStyle({
      position: "fixed",
      left,
      top,
      width,
      zIndex: 9999,
    });
  }, [requires, when]);

  React.useEffect(() => {
    if (!isOpen) {
      return;
    }

    updatePosition();
    const handleViewportChange = () => updatePosition();
    window.addEventListener("scroll", handleViewportChange, true);
    window.addEventListener("resize", handleViewportChange);

    return () => {
      window.removeEventListener("scroll", handleViewportChange, true);
      window.removeEventListener("resize", handleViewportChange);
    };
  }, [isOpen, updatePosition]);

  return (
    <span
      ref={triggerRef}
      className="inline-flex shrink-0"
      onMouseEnter={() => {
        updatePosition();
        setIsOpen(true);
      }}
      onMouseLeave={() => setIsOpen(false)}
    >
      <span
        aria-hidden="true"
        className={`flex h-4 w-4 cursor-help items-center justify-center rounded-full border bg-[rgba(15,23,42,0.7)] font-mono text-[10px] transition-colors ${
          isOpen
            ? "border-[rgba(99,102,241,0.4)] text-[#F8FAFC]"
            : "border-[rgba(148,163,184,0.25)] text-[#94A3B8]"
        } ${triggerClassName || ""}`}
      >
        ?
      </span>
      {isOpen && tooltipStyle && typeof document !== "undefined"
        ? createPortal(
          <span
            className="pointer-events-none rounded border border-[rgba(99,102,241,0.16)] bg-[rgba(2,6,23,0.96)] p-3 font-mono text-[10px] leading-4 text-[#CBD5E1] shadow-[0_12px_35px_rgba(2,6,23,0.5)]"
            style={tooltipStyle}
          >
            <span className="block text-[#F8FAFC]">{summary}</span>
            {requires ? (
              <span className="mt-2 block text-[#FCD34D]">Needs: {requires}</span>
            ) : null}
            {when ? (
              <span className="mt-2 block text-[#94A3B8]">Use it when: {when}</span>
            ) : null}
          </span>,
          document.body,
        )
        : null}
    </span>
  );
}
