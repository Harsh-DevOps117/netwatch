"use client";

import React from "react";
import Image from "next/image";
import onePagerSvg from "../assets/goal/one-pager.svg";
import fullWebsiteSvg from "../assets/goal/full-website.svg";
import websiteGrowthSvg from "../assets/goal/website-growth.svg";

export default function Goal() {
  return (
    <section className="w-full bg-[#E5E5E5] pt-24 pb-16 relative z-10 border-t border-black/[0.05] overflow-hidden">
      <div className="hidden lg:block absolute left-[28%] top-0 bottom-0 w-px bg-black/[0.06] pointer-events-none z-0 border-r border-black/[0.02] border-dashed"></div>

      <div className="w-full flex flex-col items-center mb-24 px-4 relative z-10">
        <div className="bg-[#0033FF] text-white text-[10px] sm:text-xs font-semibold tracking-widest uppercase px-3 py-1 mb-8">
          OUR SERVICES
        </div>
        <h2 className="text-[clamp(32px,3vw,48px)] leading-[1.1] font-normal tracking-tight text-[#222222] uppercase text-center max-w-2xl mb-4">
          THREE OPTIONS. ONE GOAL.
        </h2>
      </div>

      <div className="w-full relative group">
        <div className="w-full flex items-center px-4 md:px-8 xl:px-12 pt-8 pb-10">
          <span className="text-xs font-mono font-bold mr-4 md:mr-6 text-[#222]">01</span>
          <h3 className="text-3xl md:text-4xl font-normal tracking-tight whitespace-nowrap text-[#222]">Network Ingestion</h3>
          <div className="flex-1 h-[1px] bg-black/[0.15] mx-4 md:mx-8"></div>
          <div className="flex items-center gap-2 text-xs font-medium whitespace-nowrap text-[#222]">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            Real-Time
          </div>
        </div>

        <div className="max-w-[1600px] w-full px-4 md:px-8 xl:px-12 grid grid-cols-1 lg:grid-cols-12 gap-8 pb-16 relative z-10">
          <div className="lg:col-span-4 lg:pr-12 xl:pr-16 flex items-start mt-2">
            <p className="text-[#444] text-sm md:text-base leading-relaxed">
              A streamlined data pipeline that ingests flow-level and packet-level features. Captures aggregate behavior and sequencing patterns designed by attackers to evade thresholds.
            </p>
          </div>
          
          <div className="lg:col-span-5 flex flex-col justify-start items-start lg:pl-8 xl:pl-16 gap-[8px] mt-2">
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Flow-Level Vectors,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Packet-Level Timing,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Feature Engineering,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Telemetry Parsing</a>
          </div>

          <div className="lg:col-span-3 flex items-start justify-start lg:justify-end">
            <div className="w-[120px] h-[120px] relative">
              <Image src={onePagerSvg} alt="Network Ingestion" fill className="object-contain" />
            </div>
          </div>
        </div>
      </div>

      <div className="w-full relative group">
        <div className="w-full flex items-center px-4 md:px-8 xl:px-12 pt-8 pb-10">
          <span className="text-xs font-mono font-bold mr-4 md:mr-6 text-[#222]">02</span>
          <h3 className="text-3xl md:text-4xl font-normal tracking-tight whitespace-nowrap text-[#222]">World Model</h3>
          <div className="flex-1 h-[1px] bg-black/[0.15] mx-4 md:mx-8"></div>
          <div className="flex items-center gap-2 text-xs font-medium whitespace-nowrap text-[#222]">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            Continuous
          </div>
        </div>

        <div className="max-w-[1600px] w-full px-4 md:px-8 xl:px-12 grid grid-cols-1 lg:grid-cols-12 gap-8 pb-16 relative z-10">
          <div className="lg:col-span-4 lg:pr-12 xl:pr-16 flex items-start mt-2">
            <p className="text-[#444] text-sm md:text-base leading-relaxed">
              Learn state-transition dynamics using advanced AI. Given the current observed network state, the model calculates the probability distribution over future states.
            </p>
          </div>
          
          <div className="lg:col-span-5 flex flex-col justify-start items-start lg:pl-8 xl:pl-16 gap-[8px] mt-2">
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Graph Neural Networks,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Temporal Fusion,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Transition Dynamics,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Forward Simulation</a>
          </div>

          <div className="lg:col-span-3 flex items-start justify-start lg:justify-end">
            <div className="w-[120px] h-[120px] relative">
              <Image src={fullWebsiteSvg} alt="World Model" fill className="object-contain" />
            </div>
          </div>
        </div>
      </div>

      <div className="w-full relative group">
        <div className="w-full flex items-center px-4 md:px-8 xl:px-12 pt-8 pb-10">
          <span className="text-xs font-mono font-bold mr-4 md:mr-6 text-[#222]">03</span>
          <h3 className="text-3xl md:text-4xl font-normal tracking-tight whitespace-nowrap text-[#222]">Predictive Defence</h3>
          <div className="flex-1 h-[1px] bg-black/[0.15] mx-4 md:mx-8"></div>
          <div className="flex items-center gap-2 text-xs font-medium whitespace-nowrap text-[#222]">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            Proactive
          </div>
        </div>

        <div className="max-w-[1600px] w-full px-4 md:px-8 xl:px-12 grid grid-cols-1 lg:grid-cols-12 gap-8 pb-16 relative z-10">
          <div className="lg:col-span-4 lg:pr-12 xl:pr-16 flex items-start mt-2">
            <p className="text-[#444] text-sm md:text-base leading-relaxed">
              Forecast future network states and estimate the probability of attacker progression. Maps predicted behavior to MITRE ATT&CK stages and provides actionable explainability.
            </p>
          </div>
          
          <div className="lg:col-span-5 flex flex-col justify-start items-start lg:pl-8 xl:pl-16 gap-[8px] mt-2">
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Threat Forecasting,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">MITRE Mapping,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Attention Mechanisms,</a>
            <a href="#" className="text-[#0033FF] text-sm md:text-base font-medium hover:underline tracking-tight">Decision Support</a>
          </div>

          <div className="lg:col-span-3 flex items-start justify-start lg:justify-end">
            <div className="w-[120px] h-[120px] relative">
              <Image src={websiteGrowthSvg} alt="Predictive Defence" fill className="object-contain" />
            </div>
          </div>
        </div>
      </div>

      <div className="flex justify-center mt-12 mb-8 relative z-10">
        <button className="flex items-center group gap-[2px]">
          <span className="bg-[#0033FF] text-white text-[10px] font-semibold tracking-widest uppercase px-6 py-4 transition-colors duration-300 group-hover:bg-[#0022cc] shadow-sm">
            LET'S FORECAST YOURS
          </span>
          <div className="bg-[#0033FF] w-12 h-[46px] flex items-center justify-center transition-all duration-300 group-hover:bg-[#CCFF00] shadow-sm overflow-hidden">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="-rotate-45 text-white group-hover:text-[#0033FF] transition-all duration-300 group-hover:translate-x-1 group-hover:-translate-y-1">
              <line x1="5" y1="12" x2="19" y2="12"></line>
              <polyline points="12 5 19 12 12 19"></polyline>
            </svg>
          </div>
        </button>
      </div>
    </section>
  );
}
