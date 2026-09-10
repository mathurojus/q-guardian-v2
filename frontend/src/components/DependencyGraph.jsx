import React, { useMemo, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { FileCode, Cpu, Package, Wifi, GitCompare, ShieldAlert } from 'lucide-react';

// Source-type palette — mirrors AssetTable source badges so the graph reads
// the same as the inventory: static / binary / container / network.
const SOURCE_COLOR = {
  'static-source': '#4F7DE2', // cobalt-400 — semgrep
  static_code: '#1D48B0',     // cobalt-700 — AST
  binary: '#F59E0B',          // amber — LIEF
  container: '#0EA5E9',       // sky — trivy/syft
  cloud_kms: '#168A68',       // success — KMS
  network_live: '#0B1F3A',    // navy — live TLS
};
const DEFAULT_SOURCE_COLOR = '#98A2B3';

const MAX_LABEL = 24;

// Raw asset hostnames are structured per discovery source, e.g.
//   src:sample_target.py:7                 container:cryptography:41.0.7
//   bin:demo_pqc_target.bin:ML-KEM-768-NTT gateway.example.com
// Derive a short, meaningful on-canvas label per source:
//   src → FILE.PY:LINE   container → PKG:VER   bin → SYMBOL   else → host.
const shortLabel = (raw) => {
  let s = String(raw || '').trim();
  const parts = s.split(':');
  const kind = (parts[0] || '').toLowerCase();
  if (kind === 'src' && parts.length >= 3) {
    // file + line — keep the basename and line number
    const file = (parts[1] || '').split(/[\\/]/).pop();
    s = parts[2] ? `${file}:${parts[2]}` : file;
  } else if (kind === 'container' && parts.length >= 3) {
    // package + version
    s = parts[2] ? `${parts[1]}:${parts[2]}` : parts[1];
  } else if (kind === 'bin' && parts.length >= 2) {
    // the interesting bit is the trailing constant/symbol name
    s = parts[parts.length - 1] || parts[1];
  } else {
    s = parts.join(':');
  }
  s = s.toUpperCase();
  return s.length > MAX_LABEL ? `${s.slice(0, MAX_LABEL - 1).trimEnd()}…` : s;
};

const sourceColorOf = (sourceType) =>
  SOURCE_COLOR[(sourceType || '').toLowerCase()] || DEFAULT_SOURCE_COLOR;

const sourceLabelOf = (sourceType) =>
  ({
    'static-source': 'SEMGREP',
    static_code: 'AST',
    binary: 'BINARY',
    container: 'CONTAINER',
    cloud_kms: 'KMS',
    network_live: 'LIVE TLS',
  }[(sourceType || '').toLowerCase()] || 'OTHER');

const LEGEND = [
  ['network_live', Wifi, 'LIVE TLS ENDPOINT'],
  ['static-source', FileCode, 'SEMGREP SOURCE'],
  ['binary', Cpu, 'BINARY (LIEF)'],
  ['container', Package, 'CONTAINER IMAGE'],
];

const DependencyGraph = ({ assets }) => {
  const fgRef = useRef();

  const graphData = useMemo(() => {
    const nodes = [];
    const links = [];
    const algos = new Set();
    const divergent = (Array.isArray(assets) ? assets : []).filter((a) => !!a.divergence_flag);

    (Array.isArray(assets) ? assets : []).forEach((asset) => {
      const hostname = asset?.hostname || `unknown-${nodes.length}`;
      const risk = asset?.mosca?.risk_state || 'UNKNOWN';
      const algorithm = asset?.algorithm || 'Unknown Algorithm';
      const sourceType = asset?.source_type;

      // Asset node — colored by discovery source; critical live-TLS is red.
      nodes.push({
        id: hostname,
        name: shortLabel(hostname),
        title: hostname,
        val: 6,
        color:
          risk === 'CRITICAL' && sourceType === 'network_live'
            ? '#D92D20'
            : sourceColorOf(sourceType),
        type: 'asset',
        sourceType,
        sourceLabel: sourceLabelOf(sourceType),
        risk,
        divergent: !!asset.divergence_flag,
        divergenceFlag: asset.divergence_flag || null,
      });

      // Algorithm node
      if (!algos.has(algorithm)) {
        algos.add(algorithm);
        nodes.push({
          id: algorithm,
          name: algorithm,
          title: algorithm,
          val: 8,
          color: '#C6A15B',
          type: 'algo',
        });
      }
      links.push({ source: hostname, target: algorithm, value: 2, kind: 'uses' });
    });

    // Divergence hub: every flagged asset gets an amber edge to one node so
    // "declared vs actual" drift is visible at a glance.
    if (divergent.length > 0) {
      nodes.push({
        id: '__divergence_hub__',
        name: `${divergent.length} DECLARED-vs-ACTUAL`,
        title: `${divergent.length} asset(s) flagged — declared spec differs from detected crypto`,
        val: 12,
        color: '#D99000',
        type: 'divergence',
      });
      divergent.forEach((a) => {
        links.push({
          source: a.hostname,
          target: '__divergence_hub__',
          value: 4,
          kind: 'divergence',
          flag: a.divergence_flag,
        });
      });
    }

    return { nodes, links };
  }, [assets]);

  const paintNode = useCallback((node, ctx, globalScale) => {
    const label = node.name;
    const fontSize = 11 / globalScale;
    ctx.font = `600 ${fontSize}px "Inter", sans-serif`;
    const labelY = node.y + node.val + fontSize * 0.5 + 4 / globalScale;

    // Node shape
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
    ctx.fillStyle = node.color;
    ctx.fill();

    // Red ring for CRITICAL live-TLS assets
    if (node.risk === 'CRITICAL' && node.sourceType === 'network_live') {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.val + 2.5, 0, 2 * Math.PI, false);
      ctx.strokeStyle = '#D92D20';
      ctx.lineWidth = 2 / globalScale + 1;
      ctx.stroke();
    }

    // Amber ring for divergent (declared vs actual) assets
    if (node.divergent) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.val + 2.5, 0, 2 * Math.PI, false);
      ctx.strokeStyle = '#D99000';
      ctx.lineWidth = 2 / globalScale + 1;
      ctx.stroke();
    }

    // Label with a light halo so text stays readable over edges
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = `600 ${fontSize}px "Inter", sans-serif`;
    ctx.fillStyle = 'rgba(255,255,255,0.85)';
    const w = ctx.measureText(label).width;
    ctx.fillRect(node.x - w / 2 - 4 / globalScale, labelY - fontSize / 2 - 2 / globalScale, w + 8 / globalScale, fontSize + 4 / globalScale);
    ctx.fillStyle = '#344054';
    ctx.fillText(label, node.x, labelY);
  }, []);

  React.useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge').strength(-450);
      fgRef.current.d3Force('link').distance(175);
      fgRef.current.d3Force('center').strength(0.06);
      // Nodes need enough time to separate before the layout freezes.
      fgRef.current.d3ReheatSimulation();
    }
  }, [graphData]);

  const divergentCount = (Array.isArray(assets) ? assets : []).filter((a) => !!a.divergence_flag).length;

  return (
    <div className="glass-card bg-white h-[calc(100dvh-250px)] min-h-[520px] flex flex-col overflow-hidden border border-slate-200">
      {/* Header strip — own lane, never over the canvas */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-slate-200 shrink-0">
        <div>
          <h3 className="text-slate-900 font-bold text-[15px] tracking-tight flex items-center gap-3">
            <span className="w-1 h-6 bg-cobalt-600 inline-block rounded-full" />
            CRYPTO DEPENDENCY GRAPH
          </h3>
          <p className="text-[9px] text-slate-400 font-bold uppercase mt-0.5 tracking-widest ml-4">
            MULTI-SOURCE TOPOLOGY · COLORED BY DISCOVERY VECTOR · DRAG TO PANNING · SCROLL TO ZOOM
          </p>
        </div>
        {divergentCount > 0 && (
          <div className="hidden md:flex items-center gap-1.5 text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-300 rounded px-2 py-1">
            <ShieldAlert size={12} />
            {divergentCount} DECLARED-vs-ACTUAL DRIFT
          </div>
        )}
      </div>

      <div className="flex-1 flex min-h-0">
        {/* Canvas lane */}
        <div className="flex-1 min-w-0 relative">
          <ForceGraph2D
            ref={fgRef}
            graphData={graphData}
            nodeCanvasObject={paintNode}
            nodePointerAreaPaint={(node, color, ctx) => {
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
              ctx.fill();
            }}
            linkDirectionalParticles={2}
            linkDirectionalParticleSpeed={0.002}
            linkCurvature={0.25}
            linkColor={(link) =>
              link.kind === 'divergence' ? 'rgba(217, 144, 0, 0.9)' : 'rgba(152,162,179,0.35)'
            }
            linkWidth={(link) => (link.kind === 'divergence' ? 2 : 1)}
            backgroundColor="#ffffff"
            nodeRelSize={5}
            cooldownTicks={300}
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.32}
            onEngineStop={() => {
              if (fgRef.current) fgRef.current.zoomToFit(400, 70);
            }}
          />
        </div>

        {/* Legend lane — desktop: vertical panel to the right */}
        <div className="hidden lg:flex flex-col justify-center w-[235px] shrink-0 border-l border-slate-200 px-5 py-6 gap-4 bg-slate-50/60 overflow-y-auto">
          <div>
            <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-2">Source vectors</div>
            {LEGEND.map(([key, Icon, label]) => (
              <div key={key} className="flex items-center gap-2 text-[10px] font-bold text-slate-600 py-1">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: SOURCE_COLOR[key] }} />
                <Icon size={11} className="text-slate-400 shrink-0" />
                <span className="truncate">{label}</span>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-2">Risk markers</div>
            <div className="flex items-center gap-2 text-[10px] font-bold text-slate-600 py-0.5">
              <span className="w-2.5 h-2.5 rounded-full shrink-0 bg-critical ring-2 ring-red-200" /> CRITICAL LIVE TLS
            </div>
            <div className="flex items-center gap-2 text-[10px] font-bold text-slate-600 py-0.5">
              <span className="w-2.5 h-2.5 rounded-full shrink-0 bg-amber-500" /> DIVERGENCE HUB ({divergentCount})
            </div>
            <div className="flex items-center gap-2 text-[10px] font-bold text-slate-600 py-0.5">
              <span className="w-2.5 h-2.5 rounded-full shrink-0 bg-[#C6A15B]" /> CRYPTO PRIMITIVE
            </div>
          </div>
          <div className="border-t border-slate-200 pt-3">
            <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-1.5">Declared vs actual</div>
            <p className="text-[10px] leading-relaxed text-slate-500">
              Amber edges link an asset to this hub when its declared spec drifts from what the scanner actually found.
            </p>
          </div>
        </div>
      </div>

      {/* Legend — mobile/tablet: horizontal strip under the canvas */}
      <div className="lg:hidden shrink-0 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-slate-200 px-5 py-2">
        {LEGEND.map(([key, Icon, label]) => (
          <span key={key} className="flex items-center gap-1.5 text-[9px] font-bold text-slate-500">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: SOURCE_COLOR[key] }} />
            {label}
          </span>
        ))}
        <span className="flex items-center gap-1.5 text-[9px] font-bold text-slate-500">
          <GitCompare size={10} className="text-amber-500" />
          <span className="w-4 border-t-2 border-amber-500 inline-block" /> DIVERGENCE
        </span>
      </div>
    </div>
  );
};

export default DependencyGraph;
