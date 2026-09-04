"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useRef } from "react";

gsap.registerPlugin(ScrollTrigger);

export default function ProblemStatement() {
  const textRef = useRef<HTMLHeadingElement>(null);
  const videoContainerRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);

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

    gsap.fromTo(videoContainerRef.current,
      { scale: 0.5, opacity: 0, borderRadius: "2rem" },
      {
        scale: 1,
        opacity: 1,
        borderRadius: "0rem",
        ease: "none",
        scrollTrigger: {
          trigger: videoContainerRef.current,
          start: "top 95%",
          end: "center center",
          scrub: 1,
          onEnter: () => videoRef.current?.play(),
          onLeaveBack: () => videoRef.current?.pause(),
        }
      }
    );
  }, []);

  return (
    <section id="about" className="w-full md:min-h-screen grid grid-cols-1 md:grid-cols-4 relative z-10 pt-24 md:pt-32 pb-8 md:pb-12">
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

        {/* Video Section */}
        <div className="w-full pr-4 md:pr-8 xl:pr-12 pb-8 flex justify-center perspective-[1000px]">
          <div
            ref={videoContainerRef}
            className="w-full max-w-5xl overflow-hidden shadow-2xl bg-black border border-black/[0.1] relative"
            style={{ transformOrigin: "center center" }}
          >
            <video
              ref={videoRef}
              src="/video_comp/Here_s_a_production_ready_prom.mp4"
              className="w-full h-auto object-cover opacity-90"
              loop
              muted
              playsInline
            />

            <div className="absolute inset-0 bg-black/10 mix-blend-overlay pointer-events-none"></div>
          </div>
        </div>

      </div>
    </section>
  );
}
