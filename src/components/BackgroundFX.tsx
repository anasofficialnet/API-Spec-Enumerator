"use client";

import { useEffect, useRef } from "react";

type Particle3D = {
  originalX: number;
  originalY: number;
  originalZ: number;
  x: number;
  y: number;
  z: number;
  baseRadius: number;
};

export default function BackgroundFX() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) {
      return;
    }

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    let width = 0;
    let height = 0;
    let particles: Particle3D[] = [];

    // Interaction state
    let mouseX = 0;
    let mouseY = 0;
    let targetRotationX = 0;
    let targetRotationY = 0;
    let currentRotationX = 0;
    let currentRotationY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX - width / 2) / (width / 2);
      mouseY = (e.clientY - height / 2) / (height / 2);
      targetRotationY = mouseX * 0.75;
      targetRotationX = -mouseY * 0.75;
    };

    window.addEventListener("mousemove", handleMouseMove);

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // Create 3D particles on a sphere and some inside
      const count = Math.min(Math.floor((width * height) / 8000), 160);
      particles = [];
      const radius = Math.min(width, height) * 0.45;

      for (let i = 0; i < count; i++) {
        // Distribute within a volume roughly
        const u = Math.random();
        const v = Math.random();
        const theta = u * 2.0 * Math.PI;
        const phi = Math.acos(2.0 * v - 1.0);
        // Using cube root to heavily prefer points towards the edge for a cooler look
        const r = Math.cbrt(Math.random()) * radius;

        const px = r * Math.sin(phi) * Math.cos(theta);
        const py = r * Math.sin(phi) * Math.sin(theta);
        const pz = r * Math.cos(phi);

        particles.push({
          originalX: px,
          originalY: py,
          originalZ: pz,
          x: px,
          y: py,
          z: pz,
          baseRadius: Math.random() * 1.5 + 0.5,
        });
      }
    };

    let baseAngle = 0;

    const step = () => {
      try {
        ctx.clearRect(0, 0, width, height);

        baseAngle += 0.0015; // Slow ambient rotation

        // Smooth interpolation for mouse interaction
        currentRotationX += (targetRotationX - currentRotationX) * 0.05;
        currentRotationY += (targetRotationY - currentRotationY) * 0.05;

        const rotX = currentRotationX;
        const rotY = baseAngle + currentRotationY;

        const cosX = Math.cos(rotX);
        const sinX = Math.sin(rotX);
        const cosY = Math.cos(rotY);
        const sinY = Math.sin(rotY);

        // Perspective field of view
        const fov = Math.max(width, height) * 0.8;
        const maxDistance = Math.min(width, height) * 0.25;
        const maxDistanceSq = maxDistance * maxDistance;

        // Transform particles
        for (let i = 0; i < particles.length; i++) {
          const p = particles[i];

          // Rotate around Y
          const x1 = p.originalX * cosY - p.originalZ * sinY;
          const z1 = p.originalZ * cosY + p.originalX * sinY;

          // Rotate around X
          const y2 = p.originalY * cosX - z1 * sinX;
          const z2 = z1 * cosX + p.originalY * sinX;

          p.x = x1;
          p.y = y2;
          p.z = z2;
        }

        // Sort by Z for proper depth rendering (Painter's Algorithm)
        const renderList = [...particles].sort((a, b) => b.z - a.z);

        for (let i = 0; i < renderList.length; i++) {
          const p1 = renderList[i];

          const scale1 = fov / (fov + p1.z);
          if (scale1 < 0) continue; // Behind camera

          const x2d1 = p1.x * scale1 + width / 2;
          const y2d1 = p1.y * scale1 + height / 2;

          // Draw connections for the closest items
          for (let j = i + 1; j < renderList.length; j++) {
            const p2 = renderList[j];

            const dx = p1.x - p2.x;
            const dy = p1.y - p2.y;
            const dz = p1.z - p2.z;
            const distSq = dx * dx + dy * dy + dz * dz;

            if (distSq < maxDistanceSq) {
              const scale2 = fov / (fov + p2.z);
              if (scale2 < 0) continue;

              const x2d2 = p2.x * scale2 + width / 2;
              const y2d2 = p2.y * scale2 + height / 2;

              const distRatio = 1 - (distSq / maxDistanceSq);
              // Fade out points further back
              const depthAlpha = Math.max(0.02, Math.min(1, (1000 - ((p1.z + p2.z) / 2)) / 1500));
              // Multiplier to overall line brightness
              const alpha = distRatio * depthAlpha * 0.45;

              ctx.strokeStyle = `rgba(79, 195, 247, ${alpha})`;
              ctx.lineWidth = 0.6 * ((scale1 + scale2) / 2);
              ctx.beginPath();
              ctx.moveTo(x2d1, y2d1);
              ctx.lineTo(x2d2, y2d2);
              ctx.stroke();
            }
          }

          // Render node dot
          const depthAlpha = Math.max(0.05, Math.min(1, (1000 - p1.z) / 1500));
          ctx.fillStyle = `rgba(99, 102, 241, ${depthAlpha * 0.8})`;
          ctx.beginPath();
          // Glow effect for larger dots
          if (scale1 > 0.8 && p1.baseRadius > 1.2) {
            ctx.shadowBlur = 10 * scale1;
            ctx.shadowColor = "rgba(99, 102, 241, 0.5)";
          } else {
            ctx.shadowBlur = 0;
          }
          ctx.arc(x2d1, y2d1, Math.max(0.5, p1.baseRadius * scale1), 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0; // Reset shadow
        }

        rafRef.current = window.requestAnimationFrame(step);
      } catch (err) {
        // Silently catch and stop the loop to prevent react error boundaries from tripping
        console.error("Canvas 3D animation error:", err);
      }
    };

    resize();
    window.addEventListener("resize", resize);
    rafRef.current = window.requestAnimationFrame(step);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("resize", resize);
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
      }
    };
  }, []);

  return (
    <>
      <canvas ref={canvasRef} className="neuralCanvas" aria-hidden="true" />
      <div className="noiseOverlay" aria-hidden="true" />
      <div className="scanline" aria-hidden="true" />
    </>
  );
}
