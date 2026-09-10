import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FolderSearch, Zap, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronUp, ExternalLink, Sparkles,
} from 'lucide-react';
import axios from 'axios';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';

export const SCAN_MODES = {
  ast: { id: 'ast', label: 'AST (Python)', endpoint: '/scan/source', paramKey: 'target_path', placeholder: 'e.g. ./app/engines/sample_target.py or ./src', desc: 'Native AST-based discovery over source files.' },
  semgrep: { id: 'semgrep', label: 'Semgrep (rules)', endpoint: '/scan/semgrep', paramKey: 'target_path', placeholder: 'e.g. ./app or ./sample_target.py', desc: 'OWASP crypto.yml ruleset analyzer.' },
  container: { id: 'container', label: 'Container', endpoint: '/scan/container', paramKey: 'image_or_path', placeholder: 'e.g. nginx:1.24-alpine or python:3.9-slim', desc: 'Trivy/Syft SBOM inspection, with a clearly-labeled heuristic fallback.' },
  binary: { id: 'binary', label: 'Binary', endpoint: '/scan/binary', paramKey: 'filepath', placeholder: 'Path to ELF/PE, or type "SAMPLE" for the ML-KEM demo fixture', desc: 'LIEF reverse-engineering & byte-signature constant matching.' },
};

const RISK_COLOR = (score) =>
  score < 30 ? 'text-red-600' : score < 60 ? 'text-amber-600' : 'text-emerald-600';

const RISK_BG = (score) =>
  score < 30 ? 'bg-red-50 border-red-200' : score < 60 ? 'bg-amber-50 border-amber-200' : 'bg-emerald-50 border-emerald-200';

const FindingCard = ({ finding }) => {
  const [open, setOpen] = useState(false);
  const loc = finding.file || finding.offset || finding.evidence || '';
  return (
    <div className={`rounded-lg border ${RISK_BG(finding.qtri_score)} p-3 transition-all`}>
      <button
        className="w-full text-left flex items-center justify-between gap-2"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <AlertTriangle size={12} className={RISK_COLOR(finding.qtri_score)} />
          <span className="font-black text-slate-800 text-xs font-mono truncate">{finding.algorithm}</span>
          {loc && (
            <span className="text-[9px] text-slate-400 font-mono shrink-0">
              {String(loc).split(/[\\/]/).pop()}
              {finding.line ? `:${finding.line}` : ''}
            </span>
          )}
          {finding.is_pqc && (
            <span className="text-[8px] font-black font-mono text-emerald-700 bg-emerald-100 border border-emerald-300 px-1 rounded">
              PQC
            </span>
          )}
          {finding.confidence === 'low' && (
            <span className="text-[8px] font-black font-mono text-amber-700 bg-amber-100 border border-amber-300 px-1 rounded" title="Estimated — the underlying image/binary was not directly inspected">
              ESTIMATE
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[10px] font-black font-mono ${RISK_COLOR(finding.qtri_score)}`}>
            QTRI {finding.qtri_score}
          </span>
          {open ? <ChevronUp size={12} className="text-slate-400" /> : <ChevronDown size={12} className="text-slate-400" />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="mt-3 pt-3 border-t border-slate-200 space-y-1.5 text-[10px] font-mono text-slate-500">
              {finding.rule_id && <div><span className="text-slate-400">Identifier: </span>{finding.rule_id}</div>}
              {finding.evidence && <div><span className="text-slate-400">Evidence: </span>{finding.evidence}</div>}
              {finding.offset && <div><span className="text-slate-400">Byte Offset: </span>{finding.offset}</div>}
              {finding.file && <div className="truncate" title={finding.file}><span className="text-slate-400">Target: </span>{finding.file}</div>}
              {finding.recommendation && (
                <div className="text-cobalt-700 mt-1 bg-cobalt-50 border border-cobalt-100 rounded px-2 py-1">
                  {'→'} {finding.recommendation}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

/**
 * Single-purpose scanner form + results panel. `modes` selects which engines
 * are offered (pass one id for a dedicated single-scanner page, or several to
 * get an internal switcher — e.g. the Source Code page offers AST + Semgrep).
 */
const ScannerPanel = ({ modes = ['ast'], onScanComplete }) => {
  const token = sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
  const modeList = modes.map((id) => SCAN_MODES[id]).filter(Boolean);
  const [activeMode, setActiveMode] = useState(modeList[0]?.id);
  const [inputVal, setInputVal] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const currentMode = modeList.find((m) => m.id === activeMode) || modeList[0];

  const runScan = async () => {
    const val = inputVal.trim();
    if (!val && currentMode.id !== 'binary') {
      setError(`Please enter a valid target for ${currentMode.label}.`);
      return;
    }
    const finalVal = (!val && currentMode.id === 'binary') ? 'SAMPLE' : val;

    setLoading(true);
    setError('');
    setResult(null);
    try {
      const payload = { [currentMode.paramKey]: finalVal };
      const res = await axios.post(`${API_BASE}${currentMode.endpoint}`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setResult(res.data);
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const criticalCount = result?.findings_summary?.filter((f) => f.qtri_score < 30).length ?? 0;
  const warnCount = result?.findings_summary?.filter((f) => f.qtri_score >= 30 && f.qtri_score < 60).length ?? 0;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass-card overflow-hidden">
      <div className="bg-slate-50/70 border-b border-slate-200 px-5 pt-4 pb-3">
        <p className="text-xs text-slate-500 font-mono">{currentMode?.desc}</p>

        {modeList.length > 1 && (
          <div className="mt-3 flex gap-1 overflow-x-auto border-t border-slate-200 pt-2 scrollbar-none">
            {modeList.map((mode) => (
              <button
                key={mode.id}
                onClick={() => { setActiveMode(mode.id); setResult(null); setError(''); }}
                className={`px-3 py-2 text-[10px] font-bold font-mono tracking-wider transition-colors border-b-2 whitespace-nowrap ${
                  activeMode === mode.id ? 'text-cobalt-700 border-cobalt-600' : 'text-slate-400 border-transparent hover:text-slate-600'
                }`}
              >
                {mode.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="p-5 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <FolderSearch size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runScan()}
              placeholder={currentMode?.placeholder}
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-9 pr-4 py-2.5 text-[11px] font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-cobalt-500 focus:bg-white focus:ring-1 focus:ring-cobalt-100 transition-colors"
            />
          </div>

          {currentMode?.id === 'binary' && (
            <button
              onClick={() => setInputVal('SAMPLE')}
              type="button"
              className="hidden sm:flex items-center gap-1 bg-cobalt-50 border border-cobalt-100 text-cobalt-700 hover:bg-cobalt-100 font-mono text-[9px] font-bold px-3 rounded-lg"
              title="Load synthesized ML-KEM NTT binary test fixture"
            >
              <Sparkles size={11} /> DEMO FIXTURE
            </button>
          )}

          <button
            onClick={runScan}
            disabled={loading}
            className="flex items-center gap-2 bg-cobalt-600 hover:bg-cobalt-700 disabled:bg-slate-200 disabled:text-slate-400 text-white font-bold text-[10px] tracking-widest px-5 py-2.5 rounded-lg transition-colors font-mono whitespace-nowrap"
          >
            {loading
              ? <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Zap size={12} />}
            {loading ? 'SCANNING…' : 'SCAN'}
          </button>
        </div>

        {error && (
          <div className="text-[11px] text-red-700 font-mono bg-red-50 border border-red-200 rounded px-3 py-2">
            {'⚠'} {error}
          </div>
        )}
      </div>

      <AnimatePresence>
        {result && (
          <motion.div
            key="results"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="px-5 pb-5 space-y-4"
          >
            <div className="bg-slate-50 rounded-xl border border-slate-200 p-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-400 uppercase tracking-widest font-mono mb-0.5">Assets Found</span>
                <span className="text-xl font-black text-slate-900 font-mono">{result.assets_found ?? result.assets_ingested}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-400 uppercase tracking-widest font-mono mb-0.5">Critical Risk</span>
                <span className="text-xl font-black text-red-600 font-mono">{criticalCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-400 uppercase tracking-widest font-mono mb-0.5">Warning</span>
                <span className="text-xl font-black text-amber-600 font-mono">{warnCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-400 uppercase tracking-widest font-mono mb-0.5">CBOM Spec</span>
                <span className="text-sm font-bold text-cobalt-700 font-mono flex items-center gap-1">
                  <CheckCircle2 size={12} /> {result.cbom_spec_version}
                </span>
              </div>
            </div>

            {result.findings_summary?.length > 0 ? (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1 scrollbar-thin">
                <div className="text-[9px] text-slate-400 uppercase tracking-widest font-mono mb-1 flex items-center gap-2">
                  <ExternalLink size={9} /> Discovered Cryptographic Primitives
                </div>
                {result.findings_summary.map((f, i) => <FindingCard key={i} finding={f} />)}
              </div>
            ) : (
              <div className="text-center py-6 text-slate-400 text-xs font-mono">
                <CheckCircle2 size={24} className="mx-auto mb-2 text-emerald-500" />
                No weak cryptographic primitives detected.
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default ScannerPanel;
