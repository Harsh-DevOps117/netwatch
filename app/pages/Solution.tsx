"use client";

import React, { useRef } from "react";
import Image from "next/image";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import mapSvg from "../assets/Solution/6974cbc80c8fcd560c92026c_map.svg";
import makeSvg from "../assets/Solution/6974cbc8861fbf07e229e1cb_make.svg";
import moveSvg from "../assets/Solution/6974cbc8367ce36cd627e7cf_move.svg";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

export default function Solution() {
  const sectionRef = useRef<HTMLElement>(null);
  const tlRef = useRef<gsap.core.Timeline>();

  useGSAP(() => {
    tlRef.current = gsap.timeline({ repeat: -1 })
      .to(".rotating-img", {
        rotation: 360,
        ease: "none",
        duration: 15
      });

    ScrollTrigger.create({
      trigger: document.body,
      start: "top top",
      end: "bottom bottom",
      onUpdate: (self) => {
        const velocity = self.getVelocity();
        const targetTimeScale = 1 + Math.abs(velocity / 300);

        gsap.to(tlRef.current, {
          timeScale: Math.min(targetTimeScale, 10),
          duration: 0.1,
          overwrite: true,
          onComplete: () => {
            gsap.to(tlRef.current, { timeScale: 1, duration: 0.5 });
          }
        });
      }
    });
  }, { scope: sectionRef });

  return (
    <section id="work" ref={sectionRef} className="w-full md:min-h-[70vh] grid grid-cols-1 md:grid-cols-4 relative z-10 border-t border-black/[0.05]">
      <div className="col-span-1 px-4 md:px-8 py-10 md:py-16 flex flex-col border-b md:border-b-0 border-black/[0.05]">
        <div className="bg-[#0033FF] text-white text-[10px] sm:text-xs font-semibold tracking-widest uppercase px-3 py-1 inline-block mb-8 self-start">
          PROCESS
        </div>
        <h2 className="text-[clamp(32px,3vw,48px)] leading-[1.1] font-normal tracking-tight text-[#222222] uppercase mb-4">
          HOW IT WORKS
        </h2>
        <p className="text-[#444444] text-sm leading-relaxed mb-12 max-w-xs">
          Here's how we build solutions that actually work:
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

      <div className="col-span-1 px-4 md:px-8 py-10 md:py-16 flex flex-col border-l border-transparent md:border-black/[0.05] border-b md:border-b-0 border-black/[0.05]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">01</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            INGEST
          </h3>
          <div className="text-[#222222] text-lg md:text-xl font-medium tracking-tight">Ingest Network Data</div>
        </div>

        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={mapSvg} alt="Ingest Network Data" width={200} height={200} className="rotating-img w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-sm md:text-base leading-relaxed text-center mt-auto">
          We are ingesting <span className="text-[#0033FF] font-medium">Network Data and packets</span> continuously to capture every detail and temporal behavior of the traffic flow.
        </p>
      </div>

      <div className="col-span-1 px-4 md:px-8 py-10 md:py-16 flex flex-col border-l border-transparent md:border-black/[0.05] border-b md:border-b-0 border-black/[0.05] bg-black/[0.02]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">02</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            MODEL
          </h3>
          <div className="text-[#222222] text-lg md:text-xl font-medium tracking-tight">GNN and TFT Models</div>
        </div>

        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={makeSvg} alt="GNN and TFT Models" width={200} height={200} className="rotating-img w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-sm md:text-base leading-relaxed text-center mt-auto">
          The ingested models go to <span className="text-[#0033FF] font-medium">Graph Neural Networks (GNN)</span> and Temporal Fusion Transformers (TFT) to learn complex transition dynamics.
        </p>
      </div>

      <div className="col-span-1 px-4 md:px-8 py-10 md:py-16 flex flex-col border-l border-transparent md:border-black/[0.05] bg-black/[0.04]">
        <div className="text-center mb-12">
          <div className="text-[#888888] text-xs font-semibold mb-1">03</div>
          <h3 className="text-[#0033FF] text-4xl font-normal tracking-tight uppercase mb-2">
            ACT
          </h3>
          <div className="text-[#222222] text-lg md:text-xl font-medium tracking-tight">Dashboard and Automation</div>
        </div>

        <div className="flex-1 flex flex-col items-center justify-center mb-12 min-h-[200px]">
          <Image src={moveSvg} alt="Dashboard and Automation" width={200} height={200} className="rotating-img w-full max-w-[180px] mx-auto opacity-80" />
        </div>

        <p className="text-[#444444] text-sm md:text-base leading-relaxed text-center mt-auto">
          Output to a score dashboard for interpretable decision support, with possible <span className="text-[#0033FF] font-medium">automated defensive measures</span> triggered dynamically.
        </p>
      </div>
    </section>
  );
}
