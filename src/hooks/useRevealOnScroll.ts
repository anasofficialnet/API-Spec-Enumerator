"use client";

import { useEffect } from "react";

export function useRevealOnScroll(selector = ".fade-up") {
  useEffect(() => {
    const makeVisible = (element: HTMLElement) => {
      element.classList.add("visible");
    };

    const elements = () =>
      Array.from(document.querySelectorAll<HTMLElement>(selector));

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      elements().forEach(makeVisible);
      return;
    }

    const observed = new WeakSet<HTMLElement>();

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }

          const element = entry.target as HTMLElement;
          makeVisible(element);
          io.unobserve(element);
        });
      },
      { threshold: 0.14, rootMargin: "0px 0px -8% 0px" },
    );

    const observeElement = (element: HTMLElement) => {
      if (observed.has(element)) {
        return;
      }

      observed.add(element);
      io.observe(element);
    };

    const scanNode = (node: Element) => {
      if (node.matches(selector)) {
        observeElement(node as HTMLElement);
      }

      node.querySelectorAll<HTMLElement>(selector).forEach(observeElement);
    };

    elements().forEach(observeElement);

    const mutationObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof Element)) {
            return;
          }

          scanNode(node);
        });
      });
    });

    mutationObserver.observe(document.body, {
      childList: true,
      subtree: true,
    });

    return () => {
      mutationObserver.disconnect();
      io.disconnect();
    };
  }, [selector]);
}
