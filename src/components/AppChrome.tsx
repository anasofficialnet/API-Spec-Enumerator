"use client";

import type { ReactNode } from "react";
import dynamic from "next/dynamic";

import ScrollProgress from "@/components/ScrollProgress";
import { useRevealOnScroll } from "@/hooks/useRevealOnScroll";

const BackgroundFX = dynamic(() => import("@/components/BackgroundFX"), {
  ssr: false,
});

const CustomCursor = dynamic(() => import("@/components/CustomCursor"), {
  ssr: false,
});

interface AppChromeProps {
  children: ReactNode;
}

export default function AppChrome({ children }: AppChromeProps) {
  useRevealOnScroll();

  return (
    <>
      <CustomCursor />
      <ScrollProgress />
      <BackgroundFX />
      <div className="app-shell">{children}</div>
    </>
  );
}
