"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { useRef } from "react";

export default function Footer() {
  const container = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      gsap.from(container.current, {
        y: 50,
        opacity: 0,
        duration: 1,
        ease: "power3.out",
        delay: 0.8,
      });
    },
    { scope: container },
  );

  return (
    <footer
      ref={container}
      className="relative z-10 w-full flex flex-wrap items-center justify-between px-2 sm:px-6 py-4 mt-auto"
    >
      <div className="flex text-[10px] sm:text-xs font-semibold tracking-widest uppercase text-[#555555] order-1">
        <a href="#" className="hover:text-black transition-colors mr-1">
          INSTAGRAM,
        </a>
        <a href="#" className="hover:text-black transition-colors">
          LINKEDIN
        </a>
      </div>

      <div className="text-[10px] sm:text-xs font-semibold tracking-widest uppercase text-[#555555] hover:text-black cursor-pointer transition-colors order-2 sm:order-3">
        IIIT BHAGALPUR
      </div>

      <div className="flex w-full sm:w-auto mt-4 sm:mt-0 justify-center sm:absolute sm:left-1/2 sm:-translate-x-1/2 items-center gap-2 text-[10px] sm:text-xs font-semibold tracking-widest text-[#0033FF] uppercase cursor-pointer hover:text-black transition-colors order-3 sm:order-2">
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <line x1="12" y1="5" x2="12" y2="19"></line>
          <polyline points="19 12 12 19 5 12"></polyline>
        </svg>
        SCROLL DOWN
      </div>
    </footer>
  );
}
