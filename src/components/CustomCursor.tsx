"use client";

import React, { useEffect, useState } from 'react';
import { DESIGN_CONFIG } from '@/lib/designConfig';

export default function CustomCursor() {
    const [enabled, setEnabled] = useState(false);
    const [position, setPosition] = useState({ x: -100, y: -100 });
    const [isHovering, setIsHovering] = useState(false);
    const [isText, setIsText] = useState(false);

    useEffect(() => {
        if (!DESIGN_CONFIG.ENABLE_CUSTOM_CURSOR) return;

        // Check if device supports hover (not a touch device)
        const isTouchDevice = window.matchMedia('(pointer: coarse)').matches;
        const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        if (isTouchDevice || reducedMotion) return;

        setEnabled(true);

        let targetX = -100;
        let targetY = -100;

        const updatePosition = (e: MouseEvent) => {
            targetX = e.clientX;
            targetY = e.clientY;
            setPosition({ x: targetX, y: targetY });
        };

        const updateHoverState = (e: MouseEvent) => {
            const target = e.target as HTMLElement;

            // Check for interactive elements
            const interactiveElements = ['A', 'BUTTON', 'INPUT', 'TEXTAREA', 'SELECT', 'LABEL'];
            const isInteractive = interactiveElements.includes(target.tagName) ||
                target.closest('a') !== null ||
                target.closest('button') !== null ||
                target.classList.contains('cursor-pointer');

            // Check for text inputs
            const textElements = ['INPUT', 'TEXTAREA'];
            const isTextInput = textElements.includes(target.tagName) &&
                (target as HTMLInputElement).type !== 'checkbox' &&
                (target as HTMLInputElement).type !== 'radio' &&
                (target as HTMLInputElement).type !== 'button' &&
                (target as HTMLInputElement).type !== 'submit';

            setIsHovering(isInteractive && !isTextInput);
            setIsText(isTextInput);
        };

        window.addEventListener('mousemove', updatePosition);
        window.addEventListener('mouseover', updateHoverState);

        // Add a class to the html element to disable default cursor globally
        document.documentElement.classList.add('custom-cursor-enabled');

        return () => {
            window.removeEventListener('mousemove', updatePosition);
            window.removeEventListener('mouseover', updateHoverState);
            document.documentElement.classList.remove('custom-cursor-enabled');
        };
    }, []);

    if (!enabled) return null;

    return (
        <>
            <div
                className={`fixed top-0 left-0 w-2 h-2 rounded-full bg-[#6366F1] pointer-events-none z-[9999] transition-opacity duration-300 mix-blend-screen ${isText ? '!w-0.5 !h-5 !rounded-none !bg-[#38BDF8]' : ''} ${isHovering ? 'opacity-0' : 'opacity-100'}`}
                style={{
                    transform: `translate3d(${position.x}px, ${position.y}px, 0) translate(-50%, -50%)`,
                    willChange: 'transform'
                }}
            />
            <div
                className={`fixed top-0 left-0 w-8 h-8 rounded-full border border-[rgba(99,102,241,0.5)] pointer-events-none z-[9998] transition-all duration-300 ease-out ${isHovering ? 'scale-[1.8] bg-[rgba(99,102,241,0.1)] border-[rgba(56,189,248,0.5)]' : 'scale-100'} ${isText ? 'opacity-0' : 'opacity-100'}`}
                style={{
                    transform: `translate3d(${position.x}px, ${position.y}px, 0) translate(-50%, -50%)`,
                    willChange: 'transform, opacity, transform, background-color'
                }}
            />
            <style jsx global>{`
        .custom-cursor-enabled, 
        .custom-cursor-enabled *, 
        .custom-cursor-enabled .hacker-btn, 
        .custom-cursor-enabled .btn, 
        .custom-cursor-enabled a, 
        .custom-cursor-enabled button {
          cursor: none !important;
        }
      `}</style>
        </>
    );
}
