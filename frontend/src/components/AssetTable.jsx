import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheck, Clock, Globe, FileCode, Package, Cloud, Cpu, Wifi,
  AlertTriangle, CheckCircle, XCircle, Terminal, GitCompare
} from 'lucide-react';

// Neutral badge chips — source is communicated by a small color dot only.
const SOURCE_META = {
  static_code:   { label: 'AST',     icon: FileCode, dot: 'bg-cobalt-600' },
  'static-source': { label: 'SEMGREP', icon: Terminal, dot: 'bg-cobalt-400' },
  binary:        { label: 'BINARY',  icon: Cpu,      dot: 'bg-amber-500' },
  container:     { label: 'DOCKER',  icon: Package,  dot: 'bg-sky-500' },
  cloud_kms:     { label: 'KMS',     icon: Cloud,    dot: 'bg-success' },
  network_live:  { label: 'LIVE',    icon: Wifi,     dot: 'bg-navy' },
};

const RISK_COLOR = {
  CRITICAL: 'text-critical',
  WARNING:  'text-warning',
  MONITOR:  'text-amber-600',
  SAFE:     'text-success',
};

const QTRI_BAR_COLOR = (score) =>
  score > 70 ? 'bg-success' : score > 40 ? 'bg-warning' : 'bg-critical';

const SourceBadge = ({ sourceType }) => {
  const cfg = SOURCE_META[sourceType] || SOURCE_META.network_live;
  const Icon = cfg.icon;
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest text-slate-600">
      <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      <Icon size={9} className="text-slate-400" /> {cfg.label}
    </span>
  );
};

const AssetTable = ({ assets, onPlaybook }) => {
  const [filterSource, setFilterSource] = useState('ALL');

  if (!assets || assets.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card p-16 flex flex-col items-center justify-center text-center"
      >
        <Cpu size={40} className="text-slate-300 mb-4" />
        <p className="text-slate-700 font-bold text-sm">No assets discovered yet.</p>
        <p className="text-slate-400 text-xs mt-1">Run a Network, Static, Binary, or Container Scan to populate the inventory.</p>
      </motion.div>
    );
  }

  const divergentCount = assets.filter(a => !!a.divergence_flag).length;

  const filteredAssets = assets.filter(a => {
    if (filterSource === 'ALL') return true;
    if (filterSource === 'DIVERGENT') return !!a.divergence_flag;
    if (filterSource === 'STATIC') return (a.source_type || '').includes('static');
    if (filterSource === 'BINARY') return a.source_type === 'binary';
    if (filterSource === 'CONTAINER') return a.source_type === 'container';
    if (filterSource === 'NETWORK') return !a.source_type || a.source_type === 'network_live';
    return true;
  });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="glass-card overflow-hidden"
    >
      {/* Header */}
      <div className="border-b border-slate-200 bg-slate-50/70 p-5 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h3 className="qg-heading">Multi-source cryptographic asset inventory</h3>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Correlated across source code, compiled binaries, container images, and live TLS endpoints
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-none">
          {['ALL', 'DIVERGENT', 'STATIC', 'BINARY', 'CONTAINER', 'NETWORK'].map(f => (
            <button
              key={f}
              onClick={() => setFilterSource(f)}
              className={`px-2.5 py-1 text-[9px] font-black font-mono rounded tracking-wider transition-all whitespace-nowrap border ${
                filterSource === f
                  ? (f === 'DIVERGENT'
                      ? 'bg-amber-500 text-white border-amber-500'
                      : 'bg-slate-900 text-white border-slate-900')
                  : 'bg-white text-slate-500 border-slate-200 hover:border-slate-300 hover:text-slate-700'
              }`}
            >
              {f === 'DIVERGENT' && divergentCount > 0 ? `⚠ DIVERGENT (${divergentCount})` : f}
            </button>
          ))}
          <span className="text-[10px] font-bold text-cobalt-700 bg-cobalt-50 border border-cobalt-100 px-2.5 py-1 rounded font-mono ml-2">
            TOTAL: {assets.length}
          </span>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-200 bg-white">
              <th className="qg-table-head px-5 py-3 whitespace-nowrap">Asset / target</th>
              <th className="qg-table-head px-5 py-3 whitespace-nowrap">Source</th>
              <th className="qg-table-head px-5 py-3 whitespace-nowrap">Algorithm / primitive</th>
              <th className="qg-table-head hidden px-5 py-3 whitespace-nowrap sm:table-cell">QTRI</th>
              <th className="qg-table-head hidden px-5 py-3 whitespace-nowrap lg:table-cell">Risk window</th>
              <th className="qg-table-head hidden px-5 py-3 whitespace-nowrap md:table-cell">Compliance</th>
              <th className="qg-table-head px-5 py-3 whitespace-nowrap text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.map((asset, idx) => {
              const mosca = asset.mosca || {};
              const riskState = mosca.risk_state || 'SAFE';

              return (
                <motion.tr
                  key={asset.id || idx}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(idx * 0.03, 0.6) }}
                  className="hover:bg-slate-50 transition-colors border-b border-slate-100 group"
                >
                  {/* Asset / Target & Evidence */}
                  <td className="px-5 py-4 max-w-[280px]">
                    <div className="font-bold text-slate-900 text-xs tracking-tight font-mono truncate">
                      {asset.hostname?.toUpperCase()}
                    </div>

                    {/* Evidence Line or Offset */}
                    {asset.evidence_file && (
                      <div className="text-[10px] text-cobalt-700 font-mono mt-0.5 truncate" title={asset.evidence_file}>
                        {'\u{1F4C4}'} {asset.evidence_file.split(/[\\/]/).slice(-2).join('/')}
                        {asset.evidence_line ? `:${asset.evidence_line}` : ''}
                      </div>
                    )}
                    {asset.evidence_offset !== null && asset.evidence_offset !== undefined && (
                      <div className="text-[10px] text-orange-600 font-mono mt-0.5">
                        {'\u2699'} Offset: 0x{Number(asset.evidence_offset).toString(16).toUpperCase()}
                        {asset.evidence_function ? ` (${asset.evidence_function})` : ''}
                      </div>
                    )}

                    {/* Divergence Flag Badge */}
                    {asset.divergence_flag && (
                      <div className="mt-1">
                        <span className="inline-flex items-center gap-1 text-[9px] font-black font-mono text-amber-700 bg-amber-50 border border-amber-300 px-1.5 py-0.5 rounded">
                          <GitCompare size={9} /> {asset.divergence_flag}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                      <span className="text-[9px] text-slate-400 font-bold tracking-widest uppercase font-mono">
                        Tier: {asset.sensitivity_tier}
                      </span>
                      {asset.discovered_endpoints_data && JSON.parse(asset.discovered_endpoints_data || '[]').length > 0 && (
                        <div className="relative group/ep">
                          <span className="text-[9px] bg-cobalt-50 text-cobalt-700 px-1.5 py-0.5 rounded border border-cobalt-100 font-black flex items-center gap-1 cursor-help font-mono">
                            <Globe size={8} /> {JSON.parse(asset.discovered_endpoints_data).length} PATHS
                          </span>
                          <div className="absolute top-full left-0 mt-1 w-56 bg-white border border-slate-200 shadow-lg rounded-lg p-2 z-50 hidden group-hover/ep:block">
                            <div className="text-[9px] text-cobalt-700 font-bold mb-1 uppercase tracking-widest">Active Surface</div>
                            <ul className="max-h-28 overflow-y-auto space-y-0.5">
                              {JSON.parse(asset.discovered_endpoints_data).slice(0, 6).map((path, pIdx) => (
                                <li key={pIdx} className="text-[10px] font-mono text-slate-500 truncate">{path}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      )}
                    </div>
                  </td>

                  {/* Source Badge */}
                  <td className="px-5 py-4">
                    <SourceBadge sourceType={asset.source_type || 'network_live'} />
                  </td>

                  {/* Algorithm & PQC Status */}
                  <td className="px-5 py-4">
                    <div className="flex flex-col gap-0.5">
                      <span className="font-bold text-slate-800 text-xs flex items-center gap-1.5">
                        {asset.is_pqc
                          ? <ShieldCheck size={12} className="text-emerald-500" />
                          : <AlertTriangle size={12} className="text-amber-500" />
                        }
                        {asset.algorithm}
                      </span>
                      <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider font-mono">
                        {asset.tls_version !== 'N/A' && asset.tls_version ? `TLS ${asset.tls_version} \u00b7 ` : ''}{asset.key_size}b
                        {asset.primitive ? ` \u00b7 ${asset.primitive}` : ''}
                      </span>
                      {asset.is_pqc
                        ? <span className="text-[9px] text-emerald-600 font-black font-mono">{'\u2713'} PQC READY (LVL {asset.nist_quantum_security_level || 3})</span>
                        : <span className="text-[9px] text-red-600 font-black font-mono">{'\u2717'} QUANTUM VULNERABLE</span>
                      }
                    </div>
                  </td>

                  {/* QTRI Score */}
                  <td className="px-5 py-4 hidden sm:table-cell">
                    <div className="flex items-center gap-2">
                      <span className="font-black text-xs text-slate-600 w-6 text-right font-mono">{asset.qtri_score}</span>
                      <div className="w-14 h-1.5 bg-slate-100 rounded-full overflow-hidden shrink-0 border border-slate-200">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${asset.qtri_score}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.04 }}
                          className={`h-full rounded-full ${QTRI_BAR_COLOR(asset.qtri_score)}`}
                        />
                      </div>
                    </div>
                  </td>

                  {/* Risk Window */}
                  <td className="px-5 py-4 hidden lg:table-cell">
                    <span className={`font-black text-[11px] flex items-center gap-1.5 font-mono ${RISK_COLOR[riskState] || RISK_COLOR.SAFE}`}>
                      <Clock size={11} />
                      {riskState === 'CRITICAL' || riskState === 'WARNING'
                        ? `${mosca.days_remaining_worst ?? '\u2014'} DAYS`
                        : riskState
                      }
                    </span>
                  </td>

                  {/* Compliance */}
                  <td className="px-5 py-4 hidden md:table-cell">
                    {asset.policy_compliant
                      ? <span className="flex items-center gap-1 text-emerald-600 text-[10px] font-black font-mono"><CheckCircle size={11} /> OK</span>
                      : <span className="flex items-center gap-1 text-red-600 text-[10px] font-black font-mono"><XCircle size={11} /> FAIL</span>
                    }
                  </td>

                  {/* Action */}
                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={() => onPlaybook(asset)}
                      className="text-[9px] font-bold uppercase text-cobalt-700 hover:bg-cobalt-600 hover:text-white border border-cobalt-200 px-3 py-1.5 rounded-lg transition-colors tracking-widest font-mono whitespace-nowrap"
                    >
                      PLAYBOOK
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
};

export default AssetTable;
