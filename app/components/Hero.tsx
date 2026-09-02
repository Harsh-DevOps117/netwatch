"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { useRef, useState } from "react";


export default function Hero() {
  const [attackText, setAttackText] = useState("DDoS Protected");
  const container = useRef<HTMLElement>(null);
  const floatBoxRef = useRef<HTMLDivElement>(null);

  const xTo = useRef<gsap.QuickToFunc | null>(null);
  const yTo = useRef<gsap.QuickToFunc | null>(null);

  const attacks = [
    "DDoS Protected",
    "Zero-Day Mitigated",
    "Botnet Blocked",
    "Ransomware Stopped",
    "APT Tracked",
    "SQLi Deflected",
  ];

  const { contextSafe } = useGSAP(
    () => {
      xTo.current = gsap.quickTo(floatBoxRef.current, "x", {
        duration: 0.5,
        ease: "power3",
      });
      yTo.current = gsap.quickTo(floatBoxRef.current, "y", {
        duration: 0.5,
        ease: "power3",
      });

      gsap.from(".hero-line", {
        y: 100,
        opacity: 0,
        duration: 1,
        stagger: 0.15,
        ease: "power4.out",
        delay: 0.3,
      });

      gsap.from(".hero-btn", {
        scale: 0.8,
        opacity: 0,
        duration: 0.8,
        ease: "back.out(1.7)",
        delay: 0.7,
      });
    },
    { scope: container },
  );

  const handlePredictedMouseMove = contextSafe((e: React.MouseEvent) => {
    xTo.current?.(e.clientX + 15);
    yTo.current?.(e.clientY + 15);
    const index = Math.floor((e.clientX + e.clientY) / 30) % attacks.length;
    setAttackText(attacks[index]);
  });

  const handlePredictedMouseEnter = contextSafe(() => {
    gsap.to(floatBoxRef.current, { opacity: 1, duration: 0.2 });
  });

  const handlePredictedMouseLeave = contextSafe(() => {
    gsap.to(floatBoxRef.current, { opacity: 0, duration: 0.2 });
  });

  return (
    <main
      ref={container}
      className="relative z-10 flex flex-col items-center justify-between w-full min-h-[calc(100vh-2rem)] sm:min-h-[calc(100vh-3rem)] md:min-h-[calc(100vh-4rem)]"
    >
      <div className="flex-1 w-full flex flex-col items-center justify-center">
        <div
          ref={floatBoxRef}
          className="pointer-events-none fixed top-0 left-0 z-[9999] opacity-0"
        >
          <div className="bg-[#CCFF00] text-[#0000FF] border border-[#0000FF] px-4 py-2 text-xs font-sans font-semibold tracking-widest uppercase shadow-lg whitespace-nowrap">
            {attackText}
          </div>
        </div>

        <div className="w-full max-w-6xl mx-auto flex flex-col items-center relative mt-20 sm:mt-0 px-4">
          <h1 className="text-[clamp(32px,6.5vw,100px)] leading-[1.1] md:leading-[0.95] font-semibold tracking-tighter text-center uppercase flex flex-col items-center w-full whitespace-nowrap text-[#222222]">
            <span className="hero-line inline-block relative">
              FORECAST YOUR
            </span>

            <span className="hero-line block mt-1 md:mt-0">
              TRAFFIC INTO{" "}
              <span
                className="relative inline-block border-[1.5px] border-[#0033FF] group cursor-crosshair px-1"
                onMouseEnter={handlePredictedMouseEnter}
                onMouseMove={handlePredictedMouseMove}
                onMouseLeave={handlePredictedMouseLeave}
              >
                PREDICTED
                <div className="absolute -top-[3.5px] -left-[3.5px] w-[5px] h-[5px] bg-[#0033FF]" />
                <div className="absolute -top-[3.5px] -right-[3.5px] w-[5px] h-[5px] bg-[#0033FF]" />
                <div className="absolute -bottom-[3.5px] -left-[3.5px] w-[5px] h-[5px] bg-[#0033FF]" />
                <div className="absolute -bottom-[3.5px] -right-[3.5px] w-[5px] h-[5px] bg-[#0033FF]" />
              </span>
            </span>
            <span className="hero-line block font-normal mt-1 md:mt-0">
              ATTACK STATES.
            </span>
          </h1>

          <div className="hero-btn mt-16 flex items-center shadow-[0_4px_20px_rgba(0,51,255,0.15)] hover:shadow-[0_8px_30px_rgba(0,51,255,0.25)] transition-shadow">
            <button className="bg-[#0033FF] hover:bg-[#0022CC] transition-colors text-white text-[10px] sm:text-xs font-semibold tracking-widest uppercase px-6 h-10 border border-[#0033FF]">
              LET'S FORECAST YOURS
            </button>
            <div className="border border-[#0033FF] border-l-0 w-10 h-10 flex items-center justify-center transition-colors hover:bg-[#0033FF] cursor-pointer group">
              <svg
                className="transition-colors stroke-[#0033FF] group-hover:stroke-white"
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <line x1="7" y1="17" x2="17" y2="7"></line>
                <polyline points="7 7 17 7 17 17"></polyline>
              </svg>
            </div>
          </div>
        </div>
      </div>

    </main>
  );
}
