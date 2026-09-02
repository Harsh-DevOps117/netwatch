"use client";

import React, { useRef } from "react";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(ScrollTrigger);

export default function ProblemStatement() {
  const textRef = useRef<HTMLHeadingElement>(null);

  useGSAP(() => {
    gsap.from(textRef.current, {
      scrollTrigger: {
        trigger: textRef.current,
        start: "top 85%",
      },
      y: 50,
      opacity: 0,
      duration: 1.2,
      ease: "power3.out",
    });
  }, []);

  return (
    <section className="w-full md:min-h-screen grid grid-cols-1 md:grid-cols-4 relative z-10 py-24 md:py-32">
      <div className="col-span-1 px-4 md:px-8 flex flex-col items-start border-b md:border-b-0 border-black/[0.05] pb-8 md:pb-0">
        <div className="bg-[#0033FF] text-white text-[10px] sm:text-xs font-semibold tracking-widest uppercase px-3 py-1 inline-block">
          PROBLEM STATEMENT
        </div>
      </div>

      <div className="col-span-1 md:col-span-3 flex flex-col border-l border-transparent md:border-black/[0.05]">
        <div className="px-4 md:px-8 xl:px-12 overflow-hidden">
          <h2 
            ref={textRef}
            className="text-[clamp(18px,2.5vw,42px)] leading-[1.3] tracking-normal text-[#222222] w-full"
            style={{ fontFamily: 'var(--font-pixel)' }}
          >
            Traditional machine learning classifiers applied to network traffic treat each flow in isolation. We need AI systems capable of learning network behaviour, <span className="bg-[#CCFF00] text-[#0000FF] px-2 leading-none inline-block pb-1 rounded-sm">anticipating attacker progression</span> and supporting <span className="text-[#0033FF] font-semibold border-b-2 border-[#0033FF]">proactive cyber defence</span> using the emerging concept of <span className="bg-[#0033FF] text-white px-2 leading-none inline-block pb-1 rounded-sm">World Models</span>.
          </h2>
        </div>

        <div className="w-full flex items-center my-16 md:my-24 pr-4 md:pr-8 xl:pr-12">
          <div className="flex-1 h-px bg-[#222222]"></div>
          <a
            href="#"
            className="pl-4 text-[#0033FF] text-xs font-semibold tracking-widest uppercase flex items-center gap-1 hover:gap-2 transition-all whitespace-nowrap"
          >
            NTRO CHALLENGE
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

        <div className="px-4 md:px-8 xl:px-12 flex flex-col pb-24">
          
          {/* Section 1: Infiltration Process */}
          <div className="mb-16">
            <h3 className="text-[#0033FF] font-semibold uppercase tracking-widest text-xs mb-8 flex items-center gap-2">
              <div className="w-2 h-2 bg-[#0033FF]" /> The Infiltration Process
            </h3>
            <div className="border border-black/[0.1] p-6 md:p-10 relative overflow-hidden group bg-white shadow-sm hover:shadow-md transition-shadow">
              <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-10">
                <div className="max-w-md">
                  <p className="text-[#222] font-medium leading-relaxed mb-4">An infiltration is a process unfolding over time, not a single anomalous packet.</p>
                  <p className="text-[#555] text-sm leading-relaxed mb-4">The solution should ingest network traffic, learn temporal behaviour, forecast future attack states and provide interpretable decision support.</p>
                  <p className="text-xs font-semibold italic text-[#0033FF]">Move beyond static classification towards predictive defence.</p>
                </div>
                <div className="flex items-center gap-1 sm:gap-2 text-[10px] sm:text-xs font-mono text-[#0033FF] bg-[#f9f9f9] p-4 sm:p-6 border border-black/[0.05] rounded-sm w-full lg:w-auto overflow-x-auto">
                  <div className="flex flex-col items-center"><div className="w-8 h-8 sm:w-10 sm:h-10 border border-[#0033FF] flex items-center justify-center bg-white shadow-sm">S₁</div><span className="text-[9px] mt-2 text-[#888] uppercase tracking-wider">Recon</span></div>
                  <div className="w-4 sm:w-8 h-[1px] bg-[#0033FF]"></div>
                  <div className="flex flex-col items-center"><div className="w-8 h-8 sm:w-10 sm:h-10 border border-[#0033FF] flex items-center justify-center bg-white shadow-sm">S₂</div><span className="text-[9px] mt-2 text-[#888] uppercase tracking-wider">Intrusion</span></div>
                  <div className="w-4 sm:w-8 h-[1px] bg-[#0033FF]"></div>
                  <div className="flex flex-col items-center"><div className="w-8 h-8 sm:w-10 sm:h-10 border border-[#0033FF] flex items-center justify-center bg-white shadow-sm">S₃</div><span className="text-[9px] mt-2 text-[#888] uppercase tracking-wider">Lateral</span></div>
                  <div className="w-4 sm:w-8 h-[1px] bg-[#0033FF] border-dashed"></div>
                  <div className="flex flex-col items-center"><div className="w-8 h-8 sm:w-10 sm:h-10 bg-[#CCFF00] text-[#0033FF] border border-[#0033FF] flex items-center justify-center shadow-sm">Sₖ</div><span className="text-[9px] mt-2 text-black font-bold uppercase tracking-wider">Compromise</span></div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Background & Objectives */}
          <div className="mb-16">
            <h3 className="text-[#0033FF] font-semibold uppercase tracking-widest text-xs mb-8 flex items-center gap-2">
              <div className="w-2 h-2 bg-[#0033FF]" /> Background & Objectives
            </h3>
            <p className="text-[#444] text-sm leading-relaxed mb-8 max-w-3xl border-l-2 border-[#CCFF00] pl-4">
              Design and develop a software prototype that learns the evolving state of a computer network from traffic telemetry and predicts the likelihood and progression of malicious activity before compromise is completed.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="border border-black/[0.1] bg-white p-6 hover:bg-[#222] hover:text-white transition-colors group cursor-crosshair flex flex-col justify-between min-h-[160px]">
                <div className="text-[10px] font-mono text-[#888] group-hover:text-[#aaa] mb-4 border border-[#eee] group-hover:border-[#444] w-6 h-6 flex items-center justify-center rounded-full">01</div>
                <p className="text-sm font-medium leading-relaxed">Represent network state using feature vectors or graphs.</p>
              </div>
              <div className="border border-black/[0.1] bg-white p-6 hover:bg-[#0033FF] hover:text-white transition-colors group cursor-crosshair flex flex-col justify-between min-h-[160px]">
                <div className="text-[10px] font-mono text-[#888] group-hover:text-[#CCFF00] mb-4 border border-[#eee] group-hover:border-[#3366FF] w-6 h-6 flex items-center justify-center rounded-full">02</div>
                <p className="text-sm font-medium leading-relaxed">Learn state-transition dynamics using sequence models, GNNs, or latent state models.</p>
              </div>
              <div className="border border-black/[0.1] bg-white p-6 hover:bg-[#CCFF00] hover:text-[#0033FF] transition-colors group cursor-crosshair flex flex-col justify-between min-h-[160px]">
                <div className="text-[10px] font-mono text-[#888] group-hover:text-[#0033FF] mb-4 border border-[#eee] group-hover:border-[#b3e600] w-6 h-6 flex items-center justify-center rounded-full">03</div>
                <p className="text-sm font-medium leading-relaxed">Forecast future network states and estimate the probability of attacker progression.</p>
              </div>
              <div className="border border-black/[0.1] bg-white p-6 hover:bg-[#222] hover:text-white transition-colors group cursor-crosshair flex flex-col justify-between min-h-[160px]">
                <div className="text-[10px] font-mono text-[#888] group-hover:text-[#aaa] mb-4 border border-[#eee] group-hover:border-[#444] w-6 h-6 flex items-center justify-center rounded-full">04</div>
                <p className="text-sm font-medium leading-relaxed">Map predicted behaviour to recognised attack stages (e.g. MITRE ATT&CK).</p>
              </div>
              <div className="border border-black/[0.1] bg-white p-6 hover:bg-[#222] hover:text-white transition-colors group cursor-crosshair flex flex-col justify-between min-h-[160px]">
                <div className="text-[10px] font-mono text-[#888] group-hover:text-[#aaa] mb-4 border border-[#eee] group-hover:border-[#444] w-6 h-6 flex items-center justify-center rounded-full">05</div>
                <p className="text-sm font-medium leading-relaxed">Provide explainability using attention mechanisms or feature attribution.</p>
              </div>
            </div>
          </div>

          {/* Section 3: World Model Architecture */}
          <div className="mb-16">
            <h3 className="text-[#0033FF] font-semibold uppercase tracking-widest text-xs mb-8 flex items-center gap-2">
              <div className="w-2 h-2 bg-[#0033FF]" /> World Model Architecture
            </h3>
            <div className="bg-[#111] p-8 md:p-12 text-white relative overflow-hidden shadow-xl">
              <div className="absolute top-0 right-0 p-4 opacity-[0.03] scale-150 origin-top-right">
                <svg width="200" height="200" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
              </div>
              
              <div className="relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                <div>
                  <p className="text-[#ccc] text-sm leading-relaxed mb-6">
                    Rather than classifying traffic, a world model learns the transition dynamics: given the current observed network state, what is the probability distribution over future states.
                  </p>
                  <p className="text-[#ccc] text-sm leading-relaxed">
                    This enables forward simulation: roll out <code className="bg-[#CCFF00] text-[#000] px-1 font-mono">K</code> steps ahead and identify whether the current trajectory converges to an infiltration state, outputting time-series probability scores and driving features.
                  </p>
                </div>
                
                <div className="flex flex-col items-center bg-[#1a1a1a] border border-[#333] p-6 md:p-8 rounded-sm">
                  <div className="text-[10px] font-mono text-[#CCFF00] mb-6 uppercase tracking-widest">Transition Dynamics</div>
                  <div className="flex items-center gap-3 md:gap-4 w-full justify-center">
                    <div className="px-4 py-3 border border-[#444] text-xs font-mono bg-black shadow-inner">S<sub className="text-[8px]">t</sub></div>
                    <div className="flex flex-col items-center shrink-0">
                      <span className="text-[9px] text-[#888] mb-2 font-mono bg-[#222] px-2 py-1 rounded-sm border border-[#333]">P(S<sub className="text-[6px]">t+1</sub> | S<sub className="text-[6px]">t</sub>)</span>
                      <svg width="24" height="12" viewBox="0 0 24 12" fill="none" stroke="#CCFF00" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><line x1="0" y1="6" x2="22" y2="6"></line><polyline points="16 0 22 6 16 12"></polyline></svg>
                    </div>
                    <div className="px-4 py-3 bg-[#0033FF] text-white border border-[#0033FF] text-xs font-mono shadow-[0_0_20px_rgba(0,51,255,0.4)] relative">
                      S<sub className="text-[8px]">t+1</sub>
                      <div className="absolute -inset-1 border border-[#0033FF]/30 animate-pulse"></div>
                    </div>
                    <div className="hidden sm:flex flex-col items-center ml-2 opacity-50 shrink-0">
                      <span className="text-[9px] text-[#888] mb-2 font-mono">Rollout K</span>
                      <svg width="24" height="12" viewBox="0 0 24 12" fill="none" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" strokeDasharray="2 2"><line x1="0" y1="6" x2="22" y2="6"></line><polyline points="16 0 22 6 16 12"></polyline></svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 4: Data & Features */}
          <div className="mb-0">
            <h3 className="text-[#0033FF] font-semibold uppercase tracking-widest text-xs mb-8 flex items-center gap-2">
              <div className="w-2 h-2 bg-[#0033FF]" /> Data & Features
            </h3>
            <p className="text-[#444] text-sm leading-relaxed mb-8 max-w-3xl border-l-2 border-[#0033FF] pl-4">
              Teams must work with both flow-level and packet-level features. The combination is required because flow-level features capture aggregate behaviour while packet-level features expose timing and sequencing patterns.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 shadow-sm">
              <div className="border border-black/[0.1] bg-white p-8 border-b md:border-b-black/[0.1] md:border-r-0 relative group overflow-hidden hover:bg-[#f9f9f9] transition-colors">
                <div className="relative z-10">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full border border-[#222] flex items-center justify-center bg-white"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg></div>
                      <h4 className="font-semibold text-sm tracking-widest uppercase">Flow-Level</h4>
                    </div>
                    <div className="text-[9px] font-mono text-[#888] uppercase tracking-widest px-2 py-1 border border-[#eee] rounded-sm bg-gray-50">Aggregate</div>
                  </div>
                  <p className="text-[#555] text-sm leading-relaxed">Captures aggregate behaviour and large-scale structural changes across the network topology.</p>
                </div>
              </div>
              <div className="border border-black/[0.1] p-8 bg-[#CCFF00] relative group overflow-hidden hover:bg-[#c2f000] transition-colors">
                <div className="relative z-10">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full border border-[#0033FF] text-[#0033FF] flex items-center justify-center bg-white"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></div>
                      <h4 className="font-semibold text-sm tracking-widest uppercase text-[#0033FF]">Packet-Level</h4>
                    </div>
                    <div className="text-[9px] font-mono text-[#0033FF] uppercase tracking-widest px-2 py-1 border border-[#0033FF]/30 rounded-sm bg-white/50">Sequencing</div>
                  </div>
                  <p className="text-[#0033FF] text-sm leading-relaxed">Exposes timing and sequencing patterns specifically designed by attackers to evade flow-based thresholds.</p>
                </div>
              </div>
            </div>
          </div>
          
        </div>
      </div>
    </section>
  );
}
