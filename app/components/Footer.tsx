import React from 'react';

const team = [
  { name: 'Harsh', url: 'https://www.linkedin.com/in/harsh-kharwar-093919282/' },
  { name: 'Vedant', url: 'https://www.linkedin.com/in/vedant-singh-1b996b313/' },
  { name: 'Kautuk', url: 'https://www.linkedin.com/in/kaustuk-pratap-singh-23291b36b/' },
  { name: 'Abhijit', url: 'https://www.linkedin.com/in/abhijit-kumar-b10080318/' },
  { name: 'Sneha', url: 'https://www.linkedin.com/in/sneha-varma13/' },
  { name: 'Yug', url: 'https://www.linkedin.com/in/yug-s-538a8a321/' },
];

export default function Footer() {
  return (
    <footer id="contact" className="w-full bg-[#E5E5E5] pt-16 pb-8 px-4 md:px-8 xl:px-12 border-t border-black/[0.05] relative z-10 flex flex-col">
      <div className="w-full flex flex-col md:flex-row justify-between items-start md:items-end mb-8 md:mb-12">
        <div className="flex flex-col gap-2 mb-8 md:mb-0">
          <div className="text-xs text-[#888]">Quick Links</div>
          <div className="flex gap-4 md:gap-6 text-sm md:text-base font-medium tracking-wide uppercase text-[#222]">
            <a href="#" className="hover:text-[#0033FF] transition-colors">HOME</a>
            <a href="#about" className="hover:text-[#0033FF] transition-colors">ABOUT</a>
            <a href="#work" className="hover:text-[#0033FF] transition-colors">WORK</a>
            <a href="#contact" className="hover:text-[#0033FF] transition-colors">CONTACT</a>
          </div>
        </div>

        <div className="flex flex-col gap-2 md:text-right">
          <div className="text-base font-bold text-[#222] tracking-wide">Team COD-I</div>
          <div className="flex flex-wrap md:justify-end gap-x-4 gap-y-2 text-sm font-medium uppercase text-[#0033FF]">
            {team.map((member) => (
              <a key={member.name} href={member.url} target="_blank" rel="noopener noreferrer" className="hover:underline">
                [ {member.name} ]
              </a>
            ))}
          </div>
        </div>
      </div>

      <div className="w-full h-px bg-black/[0.15] mb-8 md:mb-12"></div>

      <div className="w-full flex justify-center items-center overflow-hidden mb-8 md:mb-12">
        <h1 
          className="text-[clamp(3.5rem,15vw,15rem)] leading-none text-[#222] tracking-tighter font-semibold"
        >
          NetWatch
        </h1>
      </div>

      <div className="w-full text-center text-[10px] md:text-xs text-[#666] font-medium uppercase tracking-widest">
        © 2026 NetWatch. ALL RIGHTS RESERVED.
      </div>
    </footer>
  );
}
