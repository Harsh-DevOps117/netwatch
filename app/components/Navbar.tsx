"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { useRef, useState } from "react";
import MenuOverlay from "./MenuOverlay";

export default function Navbar() {
  const container = useRef<HTMLElement>(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  useGSAP(
    () => {
      gsap.from(container.current, {
        y: -100,
        opacity: 0,
        duration: 1,
        ease: "power4.out",
        delay: 0.2,
      });
    },
    { scope: container },
  );

  return (
    <>
      <header
        ref={container}
        className={`fixed top-0 left-0 w-full z-50 flex items-center justify-between p-4 sm:p-6 transition-colors duration-500`}
      >
        <div
          className={`relative px-2 py-1 sm:px-3 sm:py-1.5 flex items-center justify-center transition-colors ${isMenuOpen ? "bg-transparent text-[#CCFF00]" : "border border-[#0000FF] bg-[#CCFF00] text-[#0000FF]"}`}
        >
          {isMenuOpen && (
            <>
              <div className="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-[#CCFF00]" />
              <div className="absolute top-0 right-0 w-3 h-3 border-t-2 border-r-2 border-[#CCFF00]" />
              <div className="absolute bottom-0 left-0 w-3 h-3 border-b-2 border-l-2 border-[#CCFF00]" />
              <div className="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-[#CCFF00]" />
            </>
          )}
          <span
            className={`font-pixel font-normal text-2xl sm:text-[28px] leading-none uppercase`}
          >
            NETWATCH
          </span>
        </div>

        <div className="flex items-center gap-3 sm:gap-6">
          <div
            className={`hidden sm:flex items-center gap-2 text-xs font-semibold tracking-wider transition-colors ${isMenuOpen ? "text-[#0022AA]" : "text-[#0033FF]"}`}
          >
            <div
              className={`w-2 h-2 rounded-sm ${isMenuOpen ? "bg-[#0022AA]" : "bg-[#CCFF00]"}`}
            />
            <span>SIH - 2026</span>
          </div>
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className={`transition-all hover:scale-105 active:scale-95 text-xs sm:text-sm font-medium px-3 sm:px-4 py-1.5 sm:py-2 flex items-center gap-2 ${isMenuOpen ? "bg-[#CCFF00] text-[#0033FF] hover:bg-white" : "bg-[#0033FF] text-white hover:bg-[#0022CC]"}`}
          >
            <span>{isMenuOpen ? "×" : "+"}</span> MENU
          </button>
        </div>
      </header>

      <MenuOverlay isOpen={isMenuOpen} onClose={() => setIsMenuOpen(false)} />
    </>
  );
}
