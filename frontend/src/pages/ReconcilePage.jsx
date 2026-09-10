import { useState } from 'react';
import { motion } from 'framer-motion';
import { GitCompare } from 'lucide-react';
import axios from 'axios';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';
import { useAppData } from '../context/AppDataContext.jsx';

const ReconcilePage = () => {
  const { fetchData } = useAppData();
  const token = sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
  const [reconciling, setReconciling] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const runReconcile = async () => {
    setReconciling(true);
    setError('');
    try {
      const res = await axios.post(`${API_BASE}/cbom/reconcile`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setResult(res.data);
      if (fetchData) fetchData();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Reconciliation failed.');
    } finally {
      setReconciling(false);
    }
  };

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Cross-checks assets discovered across all scan vectors for the same
        logical service and flags "declared vs. actual" mismatches — e.g. a
        container manifest claiming modern OpenSSL while the compiled binary
        still embeds a legacy MD5 constant. Findings are tagged
        <span className="font-mono text-xs text-cobalt-700"> identity-matched</span> (high
        confidence) or <span className="font-mono text-xs text-amber-700">environment-level</span> (co-presence
        only, medium confidence).
      </p>

      <div className="glass-card p-6">
        <button
          onClick={runReconcile}
          disabled={reconciling}
          className="flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-4 py-2.5 text-xs font-black tracking-widest text-amber-700 transition-all hover:bg-amber-100 disabled:opacity-60"
        >
          {reconciling
            ? <span className="h-3 w-3 animate-spin rounded-full border-2 border-amber-500/30 border-t-amber-600" />
            : <GitCompare size={14} />}
          {reconciling ? 'CORRELATING…' : 'RUN RECONCILIATION'}
        </button>

        {error && (
          <div className="mt-4 rounded border border-red-200 bg-red-50 px-3 py-2 font-mono text-[11px] text-red-700">
            ⚠ {error}
          </div>
        )}

        {result && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="mt-5 space-y-3 rounded-xl border border-amber-300 bg-amber-50 p-4"
          >
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 font-mono text-[11px] font-black text-amber-800">
                <GitCompare size={14} /> RECONCILIATION REPORT
              </span>
              <span className="rounded border border-amber-300 bg-white px-2 py-0.5 font-mono text-[10px] text-amber-700">
                {result.maturity_label}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-center sm:grid-cols-4">
              <div className="rounded border border-slate-200 bg-white p-2">
                <div className="font-mono text-[9px] text-slate-400">Evaluated</div>
                <div className="font-mono text-sm font-bold text-slate-900">{result.total_evaluated}</div>
              </div>
              <div className="rounded border border-slate-200 bg-white p-2">
                <div className="font-mono text-[9px] text-slate-400">Divergences</div>
                <div className="font-mono text-sm font-bold text-red-600">{result.divergence_count}</div>
              </div>
              <div className="rounded border border-slate-200 bg-white p-2">
                <div className="font-mono text-[9px] text-slate-400">Updated DB</div>
                <div className="font-mono text-sm font-bold text-cobalt-700">{result.updated_records}</div>
              </div>
              <div className="rounded border border-slate-200 bg-white p-2">
                <div className="font-mono text-[9px] text-slate-400">Maturity</div>
                <div className="font-mono text-sm font-bold text-emerald-600">{result.crypto_agility_score}/5</div>
              </div>
            </div>

            {result.divergences?.length > 0 && (
              <div className="max-h-96 space-y-1.5 overflow-y-auto pr-1">
                {result.divergences.map((div, i) => (
                  <div key={i} className="space-y-1 rounded border border-red-200 bg-white p-2 font-mono text-[10px]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-red-600">{div.divergence_flag}</span>
                      <div className="flex gap-1">
                        <span className="rounded border border-slate-200 bg-slate-50 px-1 text-[8px] text-slate-500">{div.correlation}</span>
                        <span className="rounded border border-red-200 bg-red-50 px-1 text-[8px] text-red-600">{div.severity}</span>
                      </div>
                    </div>
                    <div className="text-slate-500"><span className="text-slate-400">Target: </span>{div.target}</div>
                    <div className="text-slate-600"><span className="text-slate-400">Declared: </span>{div.declared}</div>
                    <div className="text-amber-700"><span className="text-slate-400">Actual: </span>{div.actual}</div>
                  </div>
                ))}
              </div>
            )}

            {result.divergence_count === 0 && (
              <div className="py-4 text-center font-mono text-xs text-emerald-700">
                No divergences detected across current sources.
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default ReconcilePage;
