import React, { useState, useEffect } from 'react';
import { FileCode, Download, ShieldCheck, GitCompare, PlusCircle, MinusCircle, ArrowUpDown } from 'lucide-react';
import { useToast } from '../context/ToastContext.jsx';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';

const SOURCE_DOT = {
  'static-source': 'bg-cobalt-400',
  static_code: 'bg-cobalt-700',
  binary: 'bg-amber-500',
  container: 'bg-sky-500',
  network_live: 'bg-navy',
};

const DeltaPanel = ({ diff }) => {
  if (!diff) return null;

  if (diff.status !== 'completed') {
    return (
      <div className="glass-card flex items-center gap-2 px-4 py-3 font-mono text-[11px] text-slate-500">
        <GitCompare size={13} className="text-slate-400" />
        CBOM diff: {diff.detail || 'Run two scans to compare before/after inventory.'}
      </div>
    );
  }

  const Chips = ({ items, kind }) => {
    if (!items || items.length === 0) {
      return <span className="text-[9px] text-slate-400 italic">none</span>;
    }
    return (
      <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto pr-1">
        {items.slice(0, 12).map((it, i) => (
          <span key={i}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] font-medium ${
              kind === 'added'
                ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                : 'border-red-200 bg-red-50 text-red-800'
            }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${SOURCE_DOT[it.source_type] || 'bg-slate-400'}`} />
            {String(it.name).split('/').pop()} · {it.algorithm}
          </span>
        ))}
        {items.length > 12 && <span className="text-[10px] text-slate-400">+{items.length - 12} more</span>}
      </div>
    );
  };

  const srcDeltaLabel = (delta) =>
    delta && Object.keys(delta).length
      ? Object.entries(delta).map(([s, c]) => `${s}:${c}`).join(' · ')
      : '—';

  return (
    <div className="glass-card overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50/70 px-5 py-3.5">
        <span className="qg-heading flex items-center gap-2">
          <GitCompare size={15} className="text-cobalt-600" /> CBOM before / after diff
        </span>
        <span className={`qg-chip border ${diff.net_change > 0 ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : diff.net_change < 0 ? 'border-red-200 bg-red-50 text-red-700' : 'border-slate-200 text-slate-500'}`}>
          {diff.net_change > 0 ? '+' : ''}{diff.net_change} net
        </span>
      </div>

      <div className="space-y-3 p-5 text-[12px]">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-center">
            <div className="qg-label">Before (prev scan)</div>
            <div className="font-mono text-base font-semibold text-slate-900">{diff.before.total}</div>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-center">
            <div className="qg-label">After (latest scan)</div>
            <div className="font-mono text-base font-semibold text-slate-900">{diff.after.total}</div>
          </div>
          <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-2.5 text-center">
            <div className="qg-label">Added</div>
            <div className="font-mono text-base font-semibold text-emerald-700">+{diff.added_count}</div>
          </div>
          <div className="rounded-lg border border-red-200 bg-red-50 p-2.5 text-center">
            <div className="qg-label">Removed</div>
            <div className="font-mono text-base font-semibold text-red-700">−{diff.removed_count}</div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-slate-200 p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-emerald-700">
              <PlusCircle size={12} /> Newly discovered
              {diff.added_by_source && Object.keys(diff.added_by_source).length > 0 && (
                <span className="ml-auto font-mono text-[10px] font-normal text-slate-400">[{srcDeltaLabel(diff.added_by_source)}]</span>
              )}
            </div>
            <Chips items={diff.added} kind="added" />
          </div>
          <div className="rounded-lg border border-slate-200 p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-red-700">
              <MinusCircle size={12} /> No longer present
              {diff.removed_by_source && Object.keys(diff.removed_by_source).length > 0 && (
                <span className="ml-auto font-mono text-[10px] font-normal text-slate-400">[{srcDeltaLabel(diff.removed_by_source)}]</span>
              )}
            </div>
            <Chips items={diff.removed} kind="removed" />
          </div>
        </div>

        <div className="flex items-center gap-1.5 font-mono text-[10px] text-slate-400">
          <ArrowUpDown size={10} />
          Compares the two most recent scanner snapshots — added/removed primitives by source vector.
        </div>
      </div>
    </div>
  );
};

const CBOMViewer = ({ assets }) => {
  const toast = useToast();
  const [diff, setDiff] = useState(null);

  useEffect(() => {
    const token = sessionStorage.getItem(TOKEN_KEY);
    fetch(`${API_BASE}/cbom/diff`, { headers: { 'Authorization': `Bearer ${token}` } })
      .then(res => res.ok ? res.json() : null)
      .then(data => setDiff(data))
      .catch(() => setDiff(null));
  }, []);

  const cbom = {
    metadata: {
      timestamp: new Date().toISOString(),
      tool: "Q-Guardian v2.0",
      format: "CycloneDX-Compatible",
      organization: "Q-Guardian"
    },
    components: assets.map(asset => ({
      name: asset.hostname,
      type: "service",
      cryptography: {
        algorithm: asset.algorithm,
        key_size: asset.key_size,
        tls_version: asset.tls_version,
        forward_secrecy: asset.forward_secrecy
      },
      risk: {
        qtri_score: asset.qtri_score,
        mosca_status: asset.mosca.risk_state
      }
    }))
  };

  const handleDownload = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(cbom, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "Q_Guardian_CBOM.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const handlePdfDownload = async () => {
    try {
      const token = sessionStorage.getItem(TOKEN_KEY);
      const response = await fetch(`${API_BASE}/cbom/export/pdf`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('PDF export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'Q_Guardian_CBOM.pdf';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      console.error(err);
      toast.showError("Failed to export PDF. Check console for details.");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center justify-between rounded-xl border border-slate-200 bg-white p-6">
        <div className="flex items-center gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-cobalt-600 text-white">
            <ShieldCheck size={20} />
          </div>
          <div>
            <h3 className="flex items-center gap-2 text-[15px] font-bold tracking-tight text-slate-900">
              Live cryptographic bill of materials
            </h3>
            <p className="mt-0.5 text-xs text-slate-500">Real-time inventory of enterprise ciphers and certificates</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleDownload}
            className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-700 transition-colors hover:border-slate-400 hover:bg-slate-50"
          >
            JSON
          </button>
          <button
            onClick={handlePdfDownload}
            className="qg-button"
          >
            <Download size={14} /> Export PDF
          </button>
        </div>
      </div>

      <DeltaPanel diff={diff} />

      <div className="glass-card relative overflow-hidden p-0">
        <div className="absolute right-4 top-4 z-10 font-mono text-[10px] text-slate-400">read-only</div>
        <pre className="max-h-[520px] overflow-auto p-6 font-mono text-[11px] leading-relaxed text-slate-700 scrollbar-hide">
          {JSON.stringify(cbom, null, 2)}
        </pre>
      </div>
    </div>
  );
};

export default CBOMViewer;
