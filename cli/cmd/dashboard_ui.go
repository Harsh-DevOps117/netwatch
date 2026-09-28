package cmd

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netwatch | Network Intelligence</title>
<!-- Tailwind CSS v4 CDN -->
<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
<!-- Google Fonts -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">

<style>
  :root {
    --bg-dark: #050505;
    --bento-yellow: #e4ff00;
    --bento-green: #0b5034;
    --bento-pink: #ffcce0;
    --bento-white: #ffffff;
    --neon-green: #4ade80;
    --neon-blue: #0ea5e9;
    --panel-bg: #121212;
  }

  body {
    font-family: 'Inter', sans-serif;
    background-color: var(--bg-dark);
    color: #ffffff;
    overflow-x: hidden;
  }

  .font-display { font-family: 'Space Grotesk', sans-serif; }
  .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }

  /* Tab Active States */
  .tab.active {
    background-color: var(--bento-yellow) !important;
    color: #000 !important;
    box-shadow: 0 0 15px rgba(228, 255, 0, 0.4);
  }

  /* Bento Box Styles */
  .bento-card {
    border-radius: 32px;
    padding: 28px;
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(255,255,255,0.05);
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s ease;
  }
  .bento-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 40px rgba(0,0,0,0.4);
  }

  .bg-grad-pink-yellow {
    background: linear-gradient(135deg, #ffd6e6 0%, #fff280 100%);
    color: #000000;
  }

  /* Drag & Drop */
  .dragging { opacity: 0.4; transform: scale(0.95) rotate(-1deg); }
  .sortable { min-height: 50px; }
  .grip { cursor: grab; opacity: 0.3; transition: opacity 0.2s; }
  .grip:hover { opacity: 0.8; }
  .grip:active { cursor: grabbing; }

  /* Custom Scrollbar */
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: var(--bg-dark); }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 10px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.3); }

  .view { display: none; opacity: 0; }
  .view.active { display: block; animation: viewFadeIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
  @keyframes viewFadeIn {
    from { opacity: 0; transform: translateY(15px) scale(0.99); }
    to { opacity: 1; transform: translateY(0) scale(1); }
  }

  /* Map Enhancements & Animations */
  .map-edge { stroke-dasharray: 6 6; animation: dataFlow 15s linear infinite; }
  .map-edge-fast { stroke-dasharray: 4 4; animation: dataFlow 5s linear infinite; }
  @keyframes dataFlow { to { stroke-dashoffset: -200; } }

  .pulse-ring { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
  @keyframes pulse { 0% { transform: scale(1); opacity: 0.8; stroke-width: 2px; } 100% { transform: scale(3); opacity: 0; stroke-width: 0.5px; } }

  /* Utility patterns */
  .pattern-grid { background-image: radial-gradient(rgba(255,255,255,0.1) 1px, transparent 1px); background-size: 24px 24px; }
  .pattern-stripes { fill: url(#stripes); }
</style>
</head>
<body class="antialiased selection:bg-[#e4ff00] selection:text-black min-h-screen flex flex-col">

<!-- SVG Definitions -->
<svg height="0" width="0" style="position:absolute">
  <defs>
    <pattern id="stripes" width="8" height="8" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="8" stroke="currentColor" stroke-width="2.5" />
    </pattern>
    <linearGradient id="neonGlow" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#e4ff00" />
      <stop offset="100%" stop-color="#4ade80" />
    </linearGradient>
  </defs>
</svg>

<!-- Header -->
<header class="sticky top-0 z-50 bg-[#050505]/80 backdrop-blur-2xl border-b border-white/10 h-20 flex items-center justify-between px-6 lg:px-10">
  <div class="flex items-center gap-4 font-bold text-white tracking-tight text-2xl font-display">
    <div class="w-12 h-12 rounded-xl bg-white text-black flex items-center justify-center relative overflow-hidden">
      <div class="absolute inset-0 opacity-20 pattern-stripes"></div>
      <svg viewBox="0 0 24 24" class="w-7 h-7 relative z-10" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
    </div>
    Netwatch
  </div>

  <nav class="hidden xl:flex gap-1 bg-[#121212] p-1.5 rounded-full border border-white/10 shadow-inner" aria-label="Dashboard sections">
    <button class="tab active px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="overview">Overview</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="traffic">Traffic</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="flows">Flows</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="map">Network map</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="analysis">Analysis</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="forecast">Forecast</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="system">System</button>
    <button class="tab px-5 py-2.5 rounded-full text-sm font-semibold text-white/60 hover:text-white transition-all" data-view="alerts">Alerts</button>
  </nav>

  <div class="flex items-center gap-3 bg-[#121212] border border-white/10 px-5 py-2.5 rounded-full">
    <div class="relative flex h-3 w-3">
      <span id="dotPing" class="animate-ping absolute inline-flex h-full w-full rounded-full bg-white/40 opacity-75"></span>
      <span id="dot" class="relative inline-flex rounded-full h-3 w-3 bg-white/40"></span>
    </div>
    <span id="liveText" class="text-xs font-bold tracking-widest text-white/60 uppercase">Connecting</span>
  </div>
</header>

<!-- Main Workspace -->
<main class="w-full max-w-[1800px] mx-auto px-6 lg:px-10 py-10 pb-32 flex-1">

  <!-- Global Hero / Command Strip -->
  <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8 mb-10 p-8 rounded-[2.5rem] bg-[#121212] border border-white/5 relative overflow-hidden">
    <div class="absolute -right-20 -top-40 w-96 h-96 bg-[#e4ff00] opacity-[0.03] blur-[100px] rounded-full"></div>
    <div class="absolute -left-20 -bottom-40 w-96 h-96 bg-[#ffcce0] opacity-[0.03] blur-[100px] rounded-full"></div>

    <div class="relative z-10">
      <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-bold uppercase tracking-widest text-[#e4ff00] mb-4">
        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
        Deterministic Capture Engine
      </div>
      <h1 class="text-5xl font-display font-bold tracking-tight text-white mb-2">Live Interface Telemetry</h1>
      <p class="text-white/50 text-base max-w-xl">Zero simulated data. Processing raw local hardware capture windows in real-time. Target interface: <span id="heroInterface" class="font-mono text-white/90 bg-white/10 px-2 py-0.5 rounded">--</span></p>
    </div>

    <div class="relative z-10 bg-black/40 backdrop-blur-md border border-white/10 rounded-3xl p-6 flex items-center gap-8 shadow-2xl">
      <div class="flex flex-col">
        <span class="text-[11px] font-bold uppercase tracking-widest text-white/40 mb-1">Throughput</span>
        <span class="text-3xl font-mono font-bold text-white flex items-baseline gap-2">
          <span id="heroRate">0.0</span>
          <span class="text-sm text-[#e4ff00]">p/s</span>
        </span>
      </div>
      <div class="w-px h-12 bg-white/10"></div>
      <svg class="w-32 h-12" viewBox="0 0 220 22">
        <path style="stroke:var(--bento-yellow); stroke-width:2.5; fill:none; filter: drop-shadow(0 0 4px rgba(228,255,0,0.5));" d="M0 11h14l6-8 8 16 8-16 8 16 8-8h14l6-6 8 12 8-12 8 12 8-8h14l6-4 8 8 8-8 8 8 8-4h14"/>
      </svg>
    </div>
  </div>

  <!-- VIEW: OVERVIEW -->
  <section class="view active" id="overview">
    <div class="sortable grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6" id="overviewPanels" data-order-key="bento-overview">

      <!-- Card 1: Traffic Timeline -->
      <div class="bento-card bg-grad-pink-yellow col-span-1 md:col-span-2 xl:col-span-2 shadow-[0_8px_40px_rgba(255,214,230,0.15)] flex flex-col" data-key="timeline">
        <div class="flex justify-between items-start mb-4">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight">
            <div class="w-2.5 h-2.5 rounded-full bg-black"></div> Traffic Volume
          </div>
          <span class="grip bg-black/5 p-2 rounded-full"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
        </div>
        <div class="mt-2 mb-6">
          <h3 class="text-6xl font-display font-bold tracking-tighter" id="pktsTotal">0</h3>
          <p class="text-black/60 text-sm font-bold mt-1">Total packets in current window</p>
        </div>
        <div class="mt-auto h-44 relative">
          <svg class="w-full h-full overflow-visible" viewBox="0 0 700 210" preserveAspectRatio="none" role="img" aria-label="Packets per second over captured time windows">
            <g id="timelineAxes"></g>
            <path id="timelineArea" fill="#000000" opacity="0.08" d="M55 165 L680 165 Z"/>
            <path id="timeline" fill="none" stroke="#000000" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" d="M55 165 L680 165"/>
            <g id="timelinePoints"></g>
          </svg>
        </div>
      </div>

      <!-- Card 2: Protocol Donut -->
      <div class="bento-card bg-[#e4ff00] text-black shadow-[0_8px_40px_rgba(228,255,0,0.15)] flex flex-col" data-key="donut">
        <div class="flex justify-between items-start mb-4">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight">
            Protocol Share
          </div>
          <span class="grip bg-black/5 p-2 rounded-full"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
        </div>
        <div class="flex-1 flex flex-col items-center justify-center relative py-4">
          <div class="relative w-48 h-48 drop-shadow-2xl" id="protocolDonut"></div>
        </div>
      </div>

      <!-- Card 3: TCP Dynamics -->
      <div class="bento-card bg-[#0b5034] text-white shadow-[0_8px_40px_rgba(11,80,52,0.3)] flex flex-col relative" data-key="tcp">
        <div class="absolute inset-0 opacity-10 pattern-stripes text-[#4ade80]"></div>
        <div class="relative z-10 flex justify-between items-start mb-4">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight text-[#e4ff00]">
            TCP Metrics
          </div>
          <span class="grip bg-white/10 p-2 rounded-full text-white"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
        </div>
        <div class="relative z-10 mt-2 mb-8">
          <div class="flex items-center gap-3">
            <svg class="w-8 h-8 text-[#4ade80]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
            <h3 class="text-4xl font-display font-bold" id="tcpSynCount">0</h3>
          </div>
          <p class="text-[#4ade80]/70 text-xs font-bold uppercase tracking-wider mt-2">SYN Packets</p>
        </div>
        <div class="relative z-10 flex-1 flex flex-col justify-end gap-4" id="tcpBars">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- Card 4: Basic Metrics -->
      <div class="bento-card bg-[#ffcce0] text-black shadow-[0_8px_40px_rgba(255,204,224,0.15)] flex flex-col" data-key="metrics">
        <div class="flex justify-between items-start mb-4">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight">
            Traffic State
          </div>
          <span class="grip bg-black/5 p-2 rounded-full"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
        </div>
        <div class="flex-1 flex items-center justify-center relative">
          <svg class="absolute w-full h-full text-black/5 animate-[spin_60s_linear_infinite]" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="2 6"/>
            <circle cx="50" cy="50" r="25" fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="1 8"/>
            <path d="M50 -10v120M-10 50h120M10 10l80 80M10 90l80-80" stroke="currentColor" stroke-width="0.5"/>
          </svg>
          <div class="text-center z-10 bg-white/20 backdrop-blur-sm p-6 rounded-3xl border border-white/40 shadow-xl">
            <div class="text-5xl font-display font-bold" id="activeFlows">0</div>
            <div class="text-[11px] font-bold uppercase tracking-widest mt-2 opacity-70">Active Flows</div>
          </div>
        </div>
      </div>

      <!-- Card 5: Mini Map -->
      <div class="bento-card bg-[#121212] text-white col-span-1 md:col-span-2 xl:col-span-2 flex flex-col p-0 border border-white/10" data-key="map_mini">
        <div class="absolute inset-0 pattern-grid opacity-50"></div>
        <div class="relative z-10 flex justify-between items-start p-6 pb-0">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight text-white">
            Topology Glimpse
          </div>
          <div class="flex gap-2">
            <span class="text-xs font-bold bg-[#e4ff00] text-black px-3 py-1.5 rounded-full shadow-[0_0_10px_rgba(228,255,0,0.3)]" id="mapCountMini">0 Nodes</span>
            <span class="grip bg-white/5 p-1.5 rounded-full text-white hover:bg-white/10"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
          </div>
        </div>
        <div class="relative z-10 flex-1 w-full h-56 mt-2" id="graphMini"></div>
      </div>

      <!-- Card 6: IO Metrics -->
      <div class="bento-card bg-white text-black shadow-[0_8px_40px_rgba(255,255,255,0.1)] flex flex-col" data-key="io">
        <div class="flex justify-between items-start mb-6">
          <div class="flex items-center gap-2 text-sm font-bold tracking-tight">
            I/O Breakdown
          </div>
          <span class="grip bg-black/5 p-2 rounded-full"><svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg></span>
        </div>
        <div class="flex-1 flex flex-col justify-center gap-8" id="ioBars">
          <!-- Populated by JS -->
        </div>
      </div>
    </div>
  </section>

  <!-- VIEW: TRAFFIC -->
  <section class="view" id="traffic">
    <div class="bento-card bg-[#121212] border border-white/10 text-white min-h-[60vh] p-8 lg:p-12">
      <div class="mb-10">
        <h2 class="text-4xl font-display font-bold text-white mb-2">Deep Telemetry</h2>
        <p class="text-white/40 font-mono text-sm">Window-level packet statistics and mathematical aggregates.</p>
      </div>
      <div id="deepDetail" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-fr">
        <!-- Rendered via JS -->
      </div>
    </div>
  </section>

  <!-- VIEW: FLOWS -->
  <section class="view" id="flows">
    <div class="bento-card bg-[#121212] border border-white/10 text-white min-h-[70vh] p-0 overflow-hidden flex flex-col">
      <div class="p-8 pb-6 border-b border-white/10 flex justify-between items-center bg-black/20">
        <div>
          <h2 class="text-3xl font-display font-bold text-white mb-1">Active Connections</h2>
          <p class="text-white/40 text-sm">Real-time state tracking matrix.</p>
        </div>
        <div class="bg-[#e4ff00] text-black text-xs font-bold px-4 py-2 rounded-full shadow-[0_0_15px_rgba(228,255,0,0.3)] tracking-wider uppercase" id="flowCountLabel">0 Flows</div>
      </div>
      <div class="flex-1 overflow-x-auto p-6">
        <table class="w-full text-left text-sm whitespace-nowrap border-separate border-spacing-y-2">
          <thead>
            <tr>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40">Source</th>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40">Destination</th>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40">Protocol</th>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40">State</th>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40 text-right">Packets</th>
              <th class="pb-3 px-4 font-bold uppercase tracking-wider text-[10px] text-white/40 text-right">Bytes</th>
            </tr>
          </thead>
          <tbody id="flowTable"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- VIEW: NETWORK MAP -->
  <section class="view" id="map">
    <div class="bento-card bg-[#050505] border border-white/10 text-white min-h-[80vh] flex flex-col p-0 overflow-hidden relative">
      <div class="absolute inset-0 pattern-grid opacity-30"></div>
      <div class="absolute top-0 left-0 right-0 p-8 flex justify-between items-center z-20 pointer-events-none">
        <div>
          <h2 class="text-4xl font-display font-bold text-white drop-shadow-lg mb-1">Topology Map</h2>
          <p class="text-white/50 text-sm drop-shadow-md">Only traffic to and from your PC. <span class="text-[#e4ff00]">Yellow → outbound</span> · <span class="text-[#4ade80]">Green → inbound</span>.</p>
        </div>
        <div class="bg-[#4ade80] text-black text-xs font-bold px-5 py-2.5 rounded-full shadow-[0_0_20px_rgba(74,222,128,0.4)] pointer-events-auto flex items-center gap-2" id="mapCountFull">
          <div class="w-2 h-2 rounded-full bg-black animate-pulse"></div>
          0 Nodes
        </div>
      </div>
      <div class="flex-1 w-full h-full relative z-10" id="graphFull"></div>
    </div>
  </section>

  <!-- VIEW: ANALYSIS -->
  <section class="view" id="analysis">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[60vh]">
      <div class="bento-card bg-grad-pink-yellow flex flex-col justify-center items-center text-center p-12">
        <div class="text-[12px] font-bold uppercase tracking-widest text-black/50 mb-6 bg-white/30 px-4 py-2 rounded-full">Current Status</div>
        <h2 class="text-5xl font-display font-bold text-black mb-4" id="analysisState">Waiting...</h2>
        <p class="text-black/70 max-w-sm font-medium" id="analysisCopy">Evaluating active window against deterministic models.</p>
      </div>
      <div class="bento-card bg-[#121212] border border-white/10 flex flex-col p-8">
        <h3 class="text-2xl font-display font-bold text-white mb-8">Driving Features</h3>
        <div id="featureDetail" class="grid grid-cols-2 gap-4 flex-1"></div>
      </div>
    </div>
  </section>

  <!-- VIEW: FORECAST -->
  <section class="view" id="forecast">
    <div class="bento-card bg-[#0b5034] border border-[#4ade80]/30 min-h-[60vh] flex flex-col items-center justify-center relative overflow-hidden text-center p-12">
      <div class="absolute inset-0 pattern-stripes opacity-10 text-[#e4ff00]"></div>
      <div class="relative z-10">
        <div class="inline-block border border-[#e4ff00] text-[#e4ff00] px-4 py-1.5 rounded-full text-[10px] font-bold tracking-widest uppercase mb-8 shadow-[0_0_15px_rgba(228,255,0,0.2)]">World Model Offline</div>
        <div class="text-5xl font-mono text-[#4ade80] mb-8 font-bold tracking-tighter">S[t] &rarr; S[t+1]</div>
        <h2 class="text-3xl font-display font-bold text-white mb-4">No Predictions Available</h2>
        <p class="text-white/60 max-w-md mx-auto">Future state forecasting is inactive. Await local World Model service integration for probabilistic attack staging.</p>
      </div>
    </div>
  </section>

  <!-- VIEW: SYSTEM -->
  <section class="view" id="system">
    <div class="bento-card bg-[#121212] border border-white/10 text-white min-h-[60vh] p-8 lg:p-12">
      <div class="mb-10">
        <h2 class="text-4xl font-display font-bold text-white mb-2">System Context</h2>
        <p class="text-white/40 text-sm">Local environment and capture metrics.</p>
      </div>
      <div id="systemDetail" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 auto-rows-fr"></div>
    </div>
  </section>

  <!-- VIEW: ALERTS -->
  <section class="view" id="alerts">
    <div class="bento-card bg-[#121212] border border-white/10 text-white min-h-[60vh] p-8 lg:p-12">
      <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-4">
        <div>
          <h2 class="text-4xl font-display font-bold text-white mb-2">Security Indicators</h2>
          <p class="text-white/40 text-sm">Deterministic rule engine evidence.</p>
        </div>
        <span class="text-sm font-bold bg-[#ffcce0] text-black px-6 py-3 rounded-full shadow-[0_0_20px_rgba(255,204,224,0.3)] tracking-wider uppercase" id="alertCountLabel">0 Alerts</span>
      </div>
      <div id="alertList" class="flex flex-col gap-5"></div>
    </div>
  </section>

</main>

<script>
const $ = function(id) { return document.getElementById(id); };
const num = function(x) { return Number(x||0).toLocaleString(); };
const esc = function(x) { return String(x??'').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };
const bytes = function(x) {
  x = +x||0; let u=['B','KB','MB','GB'], i=0;
  while(x>=1024 && i<3) { x/=1024; i++; }
  return x.toFixed(i?1:0)+' '+u[i];
};

function emptyState(msg, isDark) {
  let c = isDark ? 'text-white/30 border-white/10 bg-white/5' : 'text-black/40 border-black/10 bg-black/5';
  return '<div class="w-full h-full min-h-[200px] flex flex-col items-center justify-center p-8 text-center border border-dashed rounded-3xl ' + c + '"><p class="text-sm font-bold uppercase tracking-wider">' + msg + '</p></div>';
}

function dataBlock(label, value, accent) {
  let color = accent ? 'text-[' + accent + ']' : 'text-white';
  let vStr = String(value);
  let sizeClass = vStr.length > 22 ? 'text-sm leading-relaxed break-all' : 'text-2xl';
  return '<div class="bg-white/5 rounded-2xl p-6 border border-white/5 hover:bg-white/10 transition-colors h-full flex flex-col justify-center"><div class="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-2 flex-none">' + label + '</div><div class="' + sizeClass + ' font-mono font-bold ' + color + '">' + vStr + '</div></div>';
}

// Navigation Tabs
document.querySelectorAll('.tab').forEach(function(b) {
  b.onclick = function() {
    document.querySelectorAll('.tab').forEach(function(x) { x.classList.remove('active'); });
    document.querySelectorAll('.view').forEach(function(x) { x.classList.remove('active'); });
    b.classList.add('active');
    $(b.dataset.view).classList.add('active');
  };
});

// Drag and Drop (Overview Only)
const gripSVG = '<svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg>';
function loadOrder(key) { try { let o = JSON.parse(localStorage.getItem('nw_order_'+key)); return Array.isArray(o) ? o : null; } catch(e) { return null; } }
function saveOrder(key,arr) { try { localStorage.setItem('nw_order_'+key, JSON.stringify(arr)); } catch(e) {} }
function dragAfterElement(container,y,x) {
  const els = [...container.querySelectorAll(':scope > [data-key]:not(.dragging)')];
  return els.reduce(function(closest, el) {
    const box = el.getBoundingClientRect();
    const offset = (y - box.top - box.height/2);
    if(offset < 0 && offset > closest.offset) return {offset:offset, element:el};
    return closest;
  },{offset:-Infinity}).element;
}
function initSortable(container) {
  if(!container) return;
  const key = container.dataset.orderKey;
  if(!key) return;
  const saved = loadOrder(key);
  if(saved) {
    const map = {};
    [...container.children].forEach(function(c) { if(c.dataset && c.dataset.key) map[c.dataset.key] = c; });
    saved.forEach(function(k) { if(map[k]) { container.appendChild(map[k]); delete map[k]; } });
    Object.values(map).forEach(function(c) { container.appendChild(c); });
  }
  let dragEl = null;
  [...container.children].forEach(function(child) {
    if(!child.dataset || !child.dataset.key) return;
    const handle = child.querySelector('.grip');
    if(handle) {
      handle.onmousedown = function() { child.draggable = true; };
      handle.onmouseup = function() { child.draggable = false; };
    }
    child.ondragstart = function(e) {
      dragEl = child;
      setTimeout(function() { child.classList.add('dragging'); }, 0);
      e.dataTransfer.effectAllowed = 'move';
    };
    child.ondragend = function() {
      child.classList.remove('dragging');
      child.draggable = false;
      dragEl = null;
      saveOrder(key, [...container.children].filter(function(c) { return c.dataset && c.dataset.key; }).map(function(c) { return c.dataset.key; }));
    };
  });
  if(!container._dragBound) {
    container._dragBound = true;
    container.addEventListener('dragover', function(e) {
      if(!dragEl) return;
      e.preventDefault();
      const after = dragAfterElement(container, e.clientY, e.clientX);
      if(after == null) container.appendChild(dragEl);
      else container.insertBefore(dragEl, after);
    });
  }
}
document.querySelectorAll('.sortable').forEach(initSortable);

function render(d) {
  let c = d.current, st = d.status || {}, sys = d.system || {};

  // Header state
  $('dot').classList.replace('bg-white/40', 'bg-[#e4ff00]');
  $('dotPing').classList.replace('bg-white/40', 'bg-[#e4ff00]');
  $('liveText').textContent = 'LIVE';
  $('liveText').classList.replace('text-white/60', 'text-[#e4ff00]');

  $('heroRate').textContent = c ? (c.packets_per_second||0).toFixed(1) : '0.0';
  $('heroInterface').textContent = st.interface || '--';

  if(!c) return;

  let direction = d.direction || {}, flows = d.flows || [], alerts = d.alerts || [], history = d.history || [];

  // Overview Counters
  $('pktsTotal').textContent = num(c.total_packets);
  $('tcpSynCount').textContent = num(c.syn_count);
  $('activeFlows').textContent = num(flows.length);
  $('flowCountLabel').textContent = flows.length + ' Flows';

  timeline(history);
  donut(c);
  tcpBarsView(c);
  ioBarsView(direction);
  details(c);
  flowsView(flows);

  // Map renders (Mini and Full)
  mapView(d.graph || {}, sys.interface_ips || [], sys.gateway_ip || '', 'graphMini', true);
  mapView(d.graph || {}, sys.interface_ips || [], sys.gateway_ip || '', 'graphFull', false);

  alertsView(alerts);
  analysisView(c, alerts);
  systemView(sys, st, c);
}

function timeline(h) {
  let windows = h.slice(-40);
  let values = windows.map(function(x) { return +x.packets_per_second || 0; });
  let max = Math.max(1, ...values);
  let left = 58, right = 680, top = 18, bottom = 165, width = right-left, height = bottom-top;
  let axes = '<line x1="'+left+'" y1="'+top+'" x2="'+left+'" y2="'+bottom+'" stroke="#000" stroke-opacity=".35" stroke-width="1"/>';
  axes += '<line x1="'+left+'" y1="'+bottom+'" x2="'+right+'" y2="'+bottom+'" stroke="#000" stroke-opacity=".35" stroke-width="1"/>';
  for(let i=0;i<=4;i++) {
    let y = bottom-(i/4)*height, value = max*i/4;
    axes += '<line x1="'+left+'" y1="'+y+'" x2="'+right+'" y2="'+y+'" stroke="#000" stroke-opacity=".12" stroke-dasharray="3 5"/>';
    axes += '<text x="'+(left-9)+'" y="'+(y+4)+'" text-anchor="end" font-size="10" font-family="ui-monospace,monospace" fill="#000" fill-opacity=".62">'+value.toFixed(value<10?1:0)+'</text>';
  }
  let ticks = Math.min(4, Math.max(1, windows.length));
  for(let i=0;i<ticks;i++) {
    let index = ticks===1 ? 0 : Math.round(i*(windows.length-1)/(ticks-1));
    let x = left+(windows.length<=1 ? 0 : index/(windows.length-1)*width);
    let stamp = new Date(windows[index].window_start);
    let label = isNaN(stamp) ? 'window '+(windows[index].window_index+1) : stamp.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    axes += '<line x1="'+x+'" y1="'+bottom+'" x2="'+x+'" y2="'+(bottom+4)+'" stroke="#000" stroke-opacity=".35"/>';
    axes += '<text x="'+x+'" y="'+(bottom+18)+'" text-anchor="middle" font-size="9" font-family="ui-monospace,monospace" fill="#000" fill-opacity=".62">'+label+'</text>';
  }
  axes += '<text x="'+left+'" y="11" font-size="10" font-weight="700" font-family="ui-monospace,monospace" fill="#000" fill-opacity=".7">PACKETS / SECOND</text>';
  $('timelineAxes').innerHTML = axes;
  if(!windows.length) { $('timeline').setAttribute('d','M'+left+' '+bottom+' L'+right+' '+bottom); $('timelineArea').setAttribute('d','M'+left+' '+bottom+' L'+right+' '+bottom+' Z'); $('timelinePoints').innerHTML=''; return; }
  let points = values.map(function(value, i) { let x = left+(windows.length<=1 ? 0 : i/(windows.length-1)*width), y = bottom-value/max*height; return [x,y]; });
  let path = 'M'+points.map(function(p){return p[0].toFixed(1)+' '+p[1].toFixed(1);}).join(' L');
  $('timeline').setAttribute('d',path);
  $('timelineArea').setAttribute('d',path+' L'+points[points.length-1][0].toFixed(1)+' '+bottom+' L'+left+' '+bottom+' Z');
  $('timelinePoints').innerHTML = points.map(function(p,i){return '<circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="3.2" fill="#000"/><title>Window '+(windows[i].window_index+1)+': '+values[i].toFixed(2)+' packets/sec</title>';}).join('');
}

function donut(c) {
  let segs = [
    { n:'TCP', v:c.tcp_packets||0 },
    { n:'UDP', v:c.udp_packets||0 },
    { n:'DNS', v:c.dns_packets||0 },
    { n:'ICMP', v:c.icmp_packets||0 }
  ];
  let other = Math.max(0, c.total_packets - segs[0].v - segs[1].v - segs[2].v - segs[3].v);
  segs.push({ n:'Other', v:other });

  let t = Math.max(1, c.total_packets), r = 70, circ = 2*Math.PI*r, offset = 0;

  let svg = '<svg viewBox="0 0 180 180" class="w-full h-full transform -rotate-90 drop-shadow-2xl">';
  svg += '<circle cx="90" cy="90" r="' + r + '" fill="none" stroke="#000000" stroke-width="28" opacity="0.1"/>';

  segs.forEach(function(s, i) {
    if(s.v === 0) return;
    let dash = (s.v/t)*circ;
    let strokeClass = 'stroke-black';
    let dashArray = dash.toFixed(2) + ' ' + (circ-dash).toFixed(2);

    if(i === 1) { dashArray = '5 8'; } // UDP dashed
    if(i === 2) { strokeClass = 'stroke-black/40'; } // DNS lighter
    if(i === 3) { dashArray = '2 5'; strokeClass = 'stroke-black/60'; } // ICMP dotted

    svg += '<circle cx="90" cy="90" r="' + r + '" fill="none" class="' + strokeClass + '" stroke-width="24" stroke-dasharray="' + dashArray + '" stroke-dashoffset="' + (-offset).toFixed(2) + '" stroke-linecap="round"/>';
    offset += dash;
  });
  svg += '</svg>';

  svg += '<div class="absolute inset-0 flex flex-col items-center justify-center">';
  svg += '<span class="text-3xl font-display font-bold text-black tracking-tighter">' + bytes(c.total_bytes) + '</span>';
  svg += '<span class="text-[9px] font-bold uppercase tracking-widest text-black/50 mt-1">Total Payload</span>';
  svg += '</div>';

  $('protocolDonut').innerHTML = svg;
}

function tcpBarsView(c) {
  let items = [
    { l:'ACK', v:c.ack_count },
    { l:'PSH', v:c.psh_count },
    { l:'RST', v:c.rst_count },
    { l:'FIN', v:c.fin_count }
  ];
  let m = Math.max(1, ...items.map(function(x) { return x.v; }));

  let html = '';
  items.forEach(function(item) {
    let pct = (100 * item.v / m).toFixed(1);
    html += '<div class="w-full flex items-center gap-4">';
    html += '<span class="w-10 text-[10px] font-bold uppercase tracking-widest text-[#4ade80]">' + item.l + '</span>';
    html += '<div class="flex-1 h-6 rounded-md bg-black/40 border border-[#4ade80]/20 p-1">';
    html += '<div class="h-full bg-[#4ade80] rounded-sm" style="width:' + pct + '%"></div>';
    html += '</div>';
    html += '<span class="w-16 text-right text-sm font-mono font-bold text-white">' + num(item.v) + '</span>';
    html += '</div>';
  });
  $('tcpBars').innerHTML = html;
}

function ioBarsView(direction) {
  let inB = direction.inbound_bytes || 0, outB = direction.outbound_bytes || 0;
  let total = Math.max(1, inB + outB);
  let inPct = (100 * inB / total).toFixed(1);
  let outPct = (100 * outB / total).toFixed(1);

  let html = '';
  html += '<div class="flex flex-col gap-3">';
  html += '<div class="flex justify-between items-end"><span class="text-sm font-bold uppercase tracking-wider">Inbound</span><span class="text-2xl font-mono font-bold bg-[#e4ff00] text-black px-3 py-1 rounded-lg shadow-md">' + bytes(inB) + '</span></div>';
  html += '<div class="w-full h-10 bg-black/5 rounded-xl border border-black/10 p-1 flex"><div class="h-full bg-black rounded-lg shadow-inner" style="width:' + inPct + '%"></div></div>';
  html += '<div class="text-right text-[11px] font-bold uppercase opacity-50">' + inPct + '% of total</div>';
  html += '</div>';

  html += '<div class="flex flex-col gap-3 mt-4">';
  html += '<div class="flex justify-between items-end"><span class="text-sm font-bold uppercase tracking-wider">Outbound</span><span class="text-2xl font-mono font-bold bg-black text-white px-3 py-1 rounded-lg shadow-md">' + bytes(outB) + '</span></div>';
  html += '<div class="w-full h-10 bg-black/5 rounded-xl border border-black/10 p-1 flex"><div class="h-full pattern-stripes text-black rounded-lg opacity-80" style="width:' + outPct + '%"></div></div>';
  html += '<div class="text-right text-[11px] font-bold uppercase opacity-50">' + outPct + '% of total</div>';
  html += '</div>';

  $('ioBars').innerHTML = html;
}

function details(c) {
  let items = [
    ['Syn/Ack Ratio', (c.syn_ack_ratio||0).toFixed(2), '#e4ff00'],
    ['TCP Window Avg', num(c.tcp_window_mean), '#ffffff'],
    ['TTL Extent', c.ttl_min + ' - ' + c.ttl_max, '#ffffff'],
    ['Payload Mean', (c.payload_mean||0).toFixed(1) + ' B', '#4ade80'],
    ['Fragmented', num(c.fragmented_packets_count), '#ffffff'],
    ['Unique Sources', num(c.unique_source_ips), '#ffffff']
  ];
  let html = '';
  items.forEach(function(x) { html += dataBlock(x[0], x[1], x[2]); });
  $('deepDetail').innerHTML = html;
}

function flowsView(a) {
  if(!a.length) {
    $('flowTable').innerHTML = '<tr><td colspan="6" class="p-8">' + emptyState('No active flows detected.', true) + '</td></tr>';
    return;
  }
  let html = '';
  a.slice(0, 150).forEach(function(f) {
    let stateColor = f.state === 'ESTABLISHED' ? 'text-[#4ade80]' : 'text-white/50';
    html += '<tr class="bg-[#1a1a1a] hover:bg-[#222] transition-colors group">';
    html += '<td class="py-4 px-4 font-mono text-sm border-l-2 border-transparent group-hover:border-[#e4ff00]">' + esc(f.initiator_ip) + '<span class="text-white/30">:' + f.initiator_port + '</span></td>';
    html += '<td class="py-4 px-4 font-mono text-sm text-white/80">' + esc(f.responder_ip) + '<span class="text-white/30">:' + f.responder_port + '</span></td>';
    html += '<td class="py-4 px-4"><span class="bg-white/10 text-white px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider border border-white/5">' + esc(f.protocol) + '</span></td>';
    html += '<td class="py-4 px-4 text-xs font-bold uppercase tracking-wider ' + stateColor + '">' + esc(f.state) + '</td>';
    html += '<td class="py-4 px-4 text-right font-mono text-sm font-bold">' + num(f.total_packets) + '</td>';
    html += '<td class="py-4 px-4 text-right font-mono text-sm font-bold text-[#e4ff00]">' + bytes(f.total_bytes) + '</td>';
    html += '</tr>';
  });
  $('flowTable').innerHTML = html;
}

function mapView(g, locals, gatewayIP, containerId, isMini) {
  let container = $(containerId);
  if(!container) return;

  let w = container.clientWidth || (isMini ? 400 : 1200);
  let h = container.clientHeight || (isMini ? 250 : 800);

  // The map is deliberately scoped to this PC. Third-party/internal host-to-host
  // edges are not shown: an edge must have exactly one local endpoint.
  let relevantEdges = (g.edges||[]).filter(function(edge) {
    let sourceIsLocal = locals.includes(edge.src_ip);
    let destinationIsLocal = locals.includes(edge.dst_ip);
    return sourceIsLocal !== destinationIsLocal;
  });
  let remoteIPs = new Set();
  relevantEdges.forEach(function(edge) { remoteIPs.add(locals.includes(edge.src_ip) ? edge.dst_ip : edge.src_ip); });
  let remoteNodes = (g.nodes||[]).filter(function(n) { return remoteIPs.has(n.ip); }).slice(0, isMini ? 15 : 60);
  let visibleIPs = new Set(remoteNodes.map(function(n) { return n.ip; }));
  relevantEdges = relevantEdges.filter(function(edge) {
    return visibleIPs.has(locals.includes(edge.src_ip) ? edge.dst_ip : edge.src_ip);
  });
  let hasLocal = relevantEdges.length > 0;

  if(!remoteNodes.length && !hasLocal) {
    container.innerHTML = emptyState('No topology data.', true);
    if(containerId === 'graphMini') $('mapCountMini').textContent = '0 Nodes';
    if(containerId === 'graphFull') $('mapCountFull').innerHTML = '<div class="w-2 h-2 rounded-full bg-black"></div> 0 Nodes';
    return;
  }

  let pos = {};
  let center = [w/2, h/2];

  // Map ALL local IPs to the absolute center point so they render as a single machine
  locals.forEach(function(ip) {
    pos[ip] = center;
  });

  // Orbit layout for remote nodes
  remoteNodes.forEach(function(n,i) {
    let maxR = Math.min(w,h) * (isMini ? 0.35 : 0.45);
    if(isMini) {
      let a = -Math.PI/2 + i * 2 * Math.PI / Math.max(1, remoteNodes.length);
      pos[n.ip] = [center[0] + Math.cos(a)*maxR, center[1] + Math.sin(a)*maxR];
    } else {
      let golden_ratio = (Math.sqrt(5) + 1) / 2;
      let theta = i * 2 * Math.PI / golden_ratio;
      let r = maxR * Math.sqrt((i+0.5) / remoteNodes.length);
      pos[n.ip] = [center[0] + Math.cos(theta)*r, center[1] + Math.sin(theta)*r];
    }
  });

  let svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" class="w-full h-full drop-shadow-2xl"><defs><marker id="arrow-out" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#e4ff00"/></marker><marker id="arrow-in" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#4ade80"/></marker></defs>';

  // Arrowhead direction is the actual packet direction: PC → host is outbound;
  // host → PC is inbound. It is not inferred from a visual layout.
  relevantEdges.forEach(function(x) {
    let a = pos[x.src_ip], b = pos[x.dst_ip];
    let weight = x.packet_count || 1;
    let strokeW = isMini ? 1.5 : Math.min(5, 1+Math.log2(weight));
    let outbound = locals.includes(x.src_ip);
    let strokeColor = outbound ? '#e4ff00' : '#4ade80';
    let animClass = weight > 100 ? 'map-edge-fast' : 'map-edge';

    // Background dim line
    svg += '<line stroke="rgba(255,255,255,0.05)" stroke-width="' + (strokeW+2) + '" x1="' + a[0] + '" y1="' + a[1] + '" x2="' + b[0] + '" y2="' + b[1] + '"/>';
    // Animated glowing line
    svg += '<line class="' + animClass + '" stroke="' + strokeColor + '" stroke-width="' + strokeW + '" stroke-linecap="round" marker-end="url(#' + (outbound ? 'arrow-out' : 'arrow-in') + ')" x1="' + a[0] + '" y1="' + a[1] + '" x2="' + b[0] + '" y2="' + b[1] + '"/>';
  });

  // Draw Remote Nodes
  remoteNodes.forEach(function(x) {
    let p = pos[x.ip];
    let rBase = Math.min(isMini?6:12, (isMini?3:6) + Math.log2((x.packets_sent+x.packets_received||0)+1)*1.5);
    let hostname = (x.hostnames && x.hostnames.length) ? String(x.hostnames[0]).replace(/\.$/, '') : '';
    let nodeLabel = hostname || x.ip;

    svg += '<g transform="translate(' + p[0] + ',' + p[1] + ')">';
    let isGateway = gatewayIP && x.ip === gatewayIP;
    svg += '<circle r="' + rBase + '" fill="#121212" stroke="' + (isGateway ? '#e4ff00' : '#0ea5e9') + '" stroke-width="' + (isMini ? 2 : 3) + '"/>';
    if(isGateway && !isMini) svg += '<path d="M-10,-1 h20 v10 h-20 z M-6,-6 h12 v5 h-12 z M-6,4 h2 m4,0 h2 m4,0 h2" fill="none" stroke="#e4ff00" stroke-width="1.5"/>';
    if(!isMini) svg += '<text y="' + (rBase+14) + '" text-anchor="middle" class="text-[9px] font-mono font-bold fill-white/60">' + esc(nodeLabel) + (isGateway ? ' · ROUTER' : '') + '</text>';
    if(!isMini && hostname) svg += '<text y="' + (rBase+25) + '" text-anchor="middle" class="text-[8px] font-mono fill-white/30">' + esc(x.ip) + '</text>';
    svg += '</g>';
  });

  // Draw SINGLE Local Machine Hub (Laptop Icon)
  if(hasLocal) {
    let scale = isMini ? 0.7 : 1;
    svg += '<g transform="translate(' + center[0] + ',' + center[1] + ') scale(' + scale + ')">';

    if(!isMini) {
      svg += '<circle r="40" fill="none" stroke="#4ade80" stroke-width="1.5" class="pulse-ring"/>';
    }

    // Laptop Screen & Base
    svg += '<rect x="-20" y="-12" width="40" height="26" rx="3" fill="#121212" stroke="#e4ff00" stroke-width="2.5"/>';
    svg += '<rect x="-16" y="-8" width="32" height="18" rx="1" fill="#e4ff00" opacity="0.15"/>';
    svg += '<path d="M-26 14 L26 14 L22 19 L-22 19 Z" fill="#e4ff00"/>';

    // Wi-Fi Signal Symbol coming from the laptop
    svg += '<path d="M-10 -22 A14 14 0 0 1 10 -22" fill="none" stroke="#4ade80" stroke-width="2.5" stroke-linecap="round"/>';
    svg += '<path d="M-5 -26 A7 7 0 0 1 5 -26" fill="none" stroke="#4ade80" stroke-width="2.5" stroke-linecap="round"/>';
    svg += '<circle cx="0" cy="-18" r="2" fill="#4ade80"/>';

    if(!isMini) {
      svg += '<text y="34" text-anchor="middle" class="text-[11px] font-bold fill-[#e4ff00] tracking-widest uppercase filter drop-shadow">Your PC</text>';
    }
    svg += '</g>';
  }

  svg += '</svg>';
  container.innerHTML = svg;

  // Count only your PC plus hosts that exchanged traffic with it.
  let displayCount = remoteNodes.length + (hasLocal ? 1 : 0);
  if(containerId === 'graphMini') $('mapCountMini').textContent = displayCount + ' Nodes';
  if(containerId === 'graphFull') $('mapCountFull').innerHTML = '<div class="w-2 h-2 rounded-full bg-black animate-pulse"></div> ' + displayCount + ' Nodes';
}

function alertsView(a) {
  $('alertCountLabel').textContent = a.length + ' Alerts';
  if(!a.length) {
    $('alertList').innerHTML = emptyState('No security indicators triggered.', true);
    return;
  }

  let html = '';
  a.slice().reverse().forEach(function(x) {
    let isHi = String(x.severity||'').toUpperCase() === 'HIGH';
    let bg = isHi ? 'bg-red-500/10 border-red-500/30' : 'bg-white/5 border-white/10';
    let badge = isHi ? 'bg-red-500 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 'bg-[#e4ff00] text-black';
    let titleColor = isHi ? 'text-red-400' : 'text-white';

    html += '<div class="' + bg + ' p-6 rounded-[2rem] border flex flex-col gap-3 hover:bg-white/10 transition-colors">';
    html += '<div class="flex items-center gap-4">';
    html += '<span class="' + badge + ' px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest">' + esc(x.severity) + '</span>';
    html += '<h4 class="font-display font-bold text-xl ' + titleColor + '">' + esc(x.type) + '</h4>';
    html += '</div>';
    html += '<p class="font-mono text-sm bg-black/40 px-3 py-1.5 rounded-lg inline-block self-start text-white/70 border border-white/5">' + esc(x.source_ip||'?') + ' &rarr; ' + esc(x.destination_ip||'?') + '</p>';
    html += '<p class="text-base text-white/80 font-medium leading-relaxed max-w-3xl mt-1">' + esc(x.reason) + '</p>';
    if(x.mitre_attack_id) {
      html += '<div class="mt-2 flex items-center gap-2 text-[10px] uppercase font-bold text-white/40"><svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>' + esc(x.mitre_attack_id) + ' &middot; ' + esc(x.mitre_technique_name||'') + '</div>';
    }
    html += '</div>';
  });
  $('alertList').innerHTML = html;
}

function analysisView(c, a) {
  let threat = a.length > 0;
  $('analysisState').textContent = threat ? 'Indicators Active' : 'Nominal';
  $('analysisCopy').textContent = threat ? 'Rule evidence detected. Review Alerts tab.' : 'Evaluating active window against deterministic models. No thresholds breached.';

  let features = [
    ['Src IPs', num(c.unique_source_ips)],
    ['Dst IPs', num(c.unique_destination_ips)],
    ['Graph Density', ((c.graph&&c.graph.density)||0).toFixed(4)],
    ['SYN/s', (c.syn_per_second||0).toFixed(2)],
    ['UDP/s', (c.udp_packets_per_second||0).toFixed(2)]
  ];
  let html = '';
  features.forEach(function(x) { html += dataBlock(x[0], x[1]); });
  $('featureDetail').innerHTML = html;
}

function systemView(sys, st, c) {
  let items = [
    ['Hostname', sys.hostname||'Unknown', '#e4ff00'],
    ['OS', sys.operating_system||'Unknown'],
    ['Interface', sys.network_interface||st.interface||'Unknown'],
    ['Local IPs', (sys.interface_ips||[]).join(', ')||'Unknown'],
    ['MAC', sys.mac_address||'Unknown'],
    ['Duration', (st.capture_duration_seconds||0)+'s', '#4ade80'],
    ['Version', '1.0.0']
  ];
  let html = '';
  items.forEach(function(x) { html += dataBlock(x[0], x[1], x[2]); });
  $('systemDetail').innerHTML = html;
}

// Event Source Initialization
let stream = new EventSource('/api/stream');
stream.addEventListener('telemetry', function(e) { render(JSON.parse(e.data)); });
stream.onopen = function() {
  $('dot').classList.replace('bg-white/40', 'bg-[#e4ff00]');
  $('dotPing').classList.replace('bg-white/40', 'bg-[#e4ff00]');
  $('liveText').textContent = 'LIVE';
  $('liveText').classList.replace('text-white/60', 'text-[#e4ff00]');
};
stream.onerror = function() {
  $('dot').classList.replace('bg-[#e4ff00]', 'bg-red-500');
  $('dotPing').classList.replace('bg-[#e4ff00]', 'bg-red-500');
  $('liveText').textContent = 'RECONNECTING';
  $('liveText').classList.replace('text-[#e4ff00]', 'text-red-500');
};
</script>
</body>
</html>`
