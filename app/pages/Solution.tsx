import React from "react";
import Image from "next/image";
import mapSvg from "../assets/Solution/6974cbc80c8fcd560c92026c_map.svg";
import makeSvg from "../assets/Solution/6974cbc8861fbf07e229e1cb_make.svg";
import moveSvg from "../assets/Solution/6974cbc8367ce36cd627e7cf_move.svg";

export default function Solution() {
  return (
    <section className="w-full md:min-h-screen grid grid-cols-1 md:grid-cols-4 relative z-10 border-t border-black/[0.05]">
      <div className="col-span-1 px-4 md:px-8 py-16 md:py-24 flex flex-col border-b md:border-b-0 border-black/[0.05]">
        <div className="bg-[#0033FF] text-white text-[10px] sm:text-xs font-semibold tracking-widest uppercase px-3 py-1 inline-block mb-8 self-start">
          PROCESS
        </div>
        <h2 className="text-[clamp(32px,3vw,48px)] leading-[1.1] font-normal tracking-tight text-[#222222] uppercase mb-4">
          HOW IT WORKS
        </h2>
        <p className="text-[#444444] text-sm leading-relaxed mb-12 max-w-xs">
          Here's how we build websites that actually work:
        </p>
        <a
          href="#"
          className="text-[#0033FF] text-xs font-semibold tracking-widest uppercase flex items-center gap-1 hover:gap-2 transition-all mt-auto"
        >
          LEARN MORE
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="7" y1="17" x2="17" y2="7"></line>
            <polyline points="7 7 17 7 17 17"></polyline>
          </svg>
        </a>
      </div>

      <div className="col-span-1 px-4 md:px-8 py-16 md:py-24 flex flex-col border-l border-transparent md:border-black/[0.05] border-b md:border-b-0 border-black/[0.05]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">01</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            MAP
          </h3>
          <div className="text-[#222222] text-sm">Strategy // Structure</div>
        </div>
        
        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={mapSvg} alt="Map Strategy Structure" width={200} height={200} className="w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-xs leading-relaxed text-center mt-auto">
          We start by understanding your goals, your positioning, and what
          actually makes your brand valuable. This is where we figure out the
          story you're telling, who needs to hear it, and how to guide them from
          curious to ready to book.
        </p>
      </div>

      <div className="col-span-1 px-4 md:px-8 py-16 md:py-24 flex flex-col border-l border-transparent md:border-black/[0.05] border-b md:border-b-0 border-black/[0.05] bg-black/[0.02]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">02</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            MAKE
          </h3>
          <div className="text-[#222222] text-sm">Design // Experience</div>
        </div>
        
        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={makeSvg} alt="Make Design Experience" width={200} height={200} className="w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-xs leading-relaxed text-center mt-auto">
          Your brand gets translated into a visual journey that feels
          intentional. Every click, scroll, and CTA has a purpose. We're
          building the experience that takes your leads from "this looks
          interesting" to "I need to work with them."
        </p>
      </div>

      <div className="col-span-1 px-4 md:px-8 py-16 md:py-24 flex flex-col border-l border-transparent md:border-black/[0.05] bg-black/[0.04]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">03</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            MOVE
          </h3>
          <div className="text-[#222222] text-sm">Develop // Automate</div>
        </div>
        
        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={moveSvg} alt="Move Develop Automate" width={200} height={200} className="w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-xs leading-relaxed text-center mt-auto">
          We build it fast, clean, and scalable. Then we plug in the tools,
          automate, and set up your systems. Your website becomes something that
          works for you, educating leads, filtering out, and delivering
          qualified clients ready to book.
        </p>
      </div>
    </section>
  );
}
