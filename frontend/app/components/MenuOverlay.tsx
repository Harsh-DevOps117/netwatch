"use client";

import gsap from "gsap";
import { useEffect, useRef, useState } from "react";

export default function MenuOverlay({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const navRef = useRef<HTMLElement>(null);
  const bracketsRef = useRef<HTMLDivElement>(null);
  const [activeNav, setActiveNav] = useState("HOME");

  const navItems = ["HOME", "ABOUT", "WORK", "CONTACT"];

  useEffect(() => {
    if (isOpen) {
      gsap.to(overlayRef.current, {
        y: "0%",
        duration: 0.8,
        ease: "power4.inOut",
      });
      gsap.fromTo(
        ".menu-stagger",
        { y: 50, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.6, stagger: 0.1, delay: 0.4, ease: "power3.out" }
      );

      setTimeout(() => {
        const homeEl = document.getElementById("nav-HOME");
        if (homeEl) {
          moveBrackets(homeEl, 0);
          gsap.to(bracketsRef.current, { opacity: 1, duration: 0.3 });
        }
      }, 1100);
    } else {
      gsap.to(overlayRef.current, {
        y: "-100%",
        duration: 0.8,
        ease: "power4.inOut",
      });
      gsap.set(bracketsRef.current, { opacity: 0 });
    }
  }, [isOpen]);

  const moveBrackets = (target: HTMLElement, duration = 0.4) => {
    const nav = navRef.current;
    const brackets = bracketsRef.current;
    if (!nav || !brackets || !target) return;

    const targetRect = target.getBoundingClientRect();
    const navRect = nav.getBoundingClientRect();

    gsap.to(brackets, {
      x: targetRect.left - navRect.left,
      y: targetRect.top - navRect.top,
      width: targetRect.width,
      height: targetRect.height,
      duration,
      ease: "power3.out",
    });
  };

  const handleNavHover = (e: React.MouseEvent<HTMLAnchorElement>, item: string) => {
    setActiveNav(item);
    moveBrackets(e.currentTarget);
  };

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-40 bg-[#0033FF] flex flex-col -translate-y-full overflow-hidden"
    >
      <div className="absolute inset-0 pointer-events-none grid grid-cols-4 divide-x divide-white/10 z-0">
        <div />
        <div />
        <div />
        <div />
      </div>
      <div className="hidden md:block absolute bottom-16 left-0 w-full h-[1px] bg-white/10 z-0" />

      <div className="flex-1 w-full max-w-[1400px] mx-auto flex flex-col md:flex-row items-center md:items-start lg:items-center justify-between px-6 md:px-12 pt-24 md:pt-32 pb-8 md:pb-16 z-10 overflow-y-auto">
        <nav ref={navRef} className="flex flex-col gap-6 font-pixel font-bold text-[48px] leading-[48px] md:text-[80px] md:leading-[80px] text-white uppercase relative md:ml-[15%] lg:ml-[20%] items-center md:items-end text-center md:text-right mt-12 md:mt-0 w-full md:w-auto">

          <div
            ref={bracketsRef}
            className="absolute top-0 left-0 pointer-events-none opacity-0"
          >
            <div className="absolute -top-3 -left-4 w-3 h-3 border-t-2 border-l-2 border-[#CCFF00]" />
            <div className="absolute -top-3 -right-4 w-3 h-3 border-t-2 border-r-2 border-[#CCFF00]" />
            <div className="absolute -bottom-2 -left-4 w-3 h-3 border-b-2 border-l-2 border-[#CCFF00]" />
            <div className="absolute -bottom-2 -right-4 w-3 h-3 border-b-2 border-r-2 border-[#CCFF00]" />
          </div>

          {navItems.map((item, idx) => {
            let href = "#";
            if (item === "HOME") href = "#";
            else if (item === "ABOUT") href = "#about";
            else if (item === "WORK") href = "#work";
            else if (item === "CONTACT") href = "#contact";

            return (
              <a
                key={item}
                id={`nav-${item}`}
                href={href}
                onClick={() => onClose()}
                onMouseEnter={(e) => handleNavHover(e, item)}
                className={`menu-stagger transition-colors relative group w-fit ${activeNav === item ? 'text-[#CCFF00]' : 'text-[#E3E3E3]/70 hover:text-opacity-100'}`}
              >
                <span className="absolute -top-3 right-0 text-sm font-sans font-bold text-[#CCFF00]">0{idx + 1}</span>
                {item}
              </a>
            );
          })}
        </nav>

        <div className="flex flex-col gap-10 text-white font-sans mt-16 md:mt-0 md:mr-[10%] lg:mr-[15%] items-center md:items-start text-center md:text-left w-full md:w-auto">
          <div className="menu-stagger flex flex-col gap-3">
            <div className="text-[10px] text-[#CCFF00] font-bold uppercase tracking-widest">SOCIALS</div>
            <a href="https://www.instagram.com/" target="_blank" rel="noopener noreferrer" className="text-xs uppercase tracking-widest hover:text-[#CCFF00] transition-colors flex items-center gap-2">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"></rect><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"></path><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"></line></svg>
              INSTAGRAM
            </a>
            <a href="https://www.linkedin.com/" target="_blank" rel="noopener noreferrer" className="text-xs uppercase tracking-widest hover:text-[#CCFF00] transition-colors flex items-center gap-2">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path><rect x="2" y="9" width="4" height="12"></rect><circle cx="4" cy="4" r="2"></circle></svg>
              LINKEDIN
            </a>
          </div>

          <div className="menu-stagger flex flex-col gap-3">
            <div className="text-[10px] text-[#CCFF00] font-bold uppercase tracking-widest">E-MAIL</div>
            <div className="text-xs uppercase tracking-widest">
              [ HARSH.240103263@IIITBH.AC.IN ]
            </div>
          </div>

          <div className="menu-stagger flex flex-col gap-0 w-64 mt-2">
            <div className="bg-[#CCFF00] text-[#0033FF] text-[10px] font-bold uppercase tracking-widest px-2 py-1 w-fit">JOIN THE ARCHIVE</div>
            <input
              type="text"
              placeholder="Your Name"
              className="bg-transparent border border-[#CCFF00] text-white px-3 py-2 text-xs outline-none placeholder-white/70 focus:bg-white/10 mt-[2px]"
            />
            <input
              type="email"
              placeholder="name@example.com"
              className="bg-transparent border border-[#CCFF00] border-t-0 text-white px-3 py-2 text-xs outline-none placeholder-white/70 focus:bg-white/10"
            />
            <button className="bg-[#CCFF00] text-[#0033FF] hover:bg-white transition-colors text-xs font-bold uppercase tracking-widest px-4 py-2 w-fit mt-3">
              SUBSCRIBE
            </button>
          </div>

          {/* Mobile-only relative footer elements */}
          <div className="md:hidden w-full h-[1px] bg-white/10 mt-8 mb-6" />
          <div className="md:hidden menu-stagger flex justify-center w-full pb-8">
            <div className="text-[10px] font-bold uppercase tracking-widest text-[#E3E3E3]">
              | INSIGHTS |
            </div>
          </div>
        </div>
      </div>

      <div className="hidden md:flex menu-stagger absolute bottom-6 w-full justify-center z-10">
        <div className="text-[10px] font-bold uppercase tracking-widest text-[#E3E3E3]">
          | INSIGHTS |
        </div>
      </div>
    </div>
  );
}
