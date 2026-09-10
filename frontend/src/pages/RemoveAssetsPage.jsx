import { useMemo, useState } from 'react';
import axios from 'axios';
import { Trash2, AlertTriangle, Package, FileCode, Cpu, Globe2, Terminal, KeyRound, Check, X } from 'lucide-react';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';
import { useAppData } from '../context/AppDataContext.jsx';
import { useToast } from '../context/ToastContext.jsx';

const SOURCE_META = {
  network_live: { label: 'Network / Domain', icon: Globe2, color: 'text-cobalt-600 bg-cobalt-50 border-cobalt-100' },
  'static-source': { label: 'Source Code', icon: FileCode, color: 'text-emerald-600 bg-emerald-50 border-emerald-100' },
  static_code: { label: 'Source Code', icon: FileCode, color: 'text-emerald-600 bg-emerald-50 border-emerald-100' },
  container: { label: 'Container Image', icon: Package, color: 'text-amber-600 bg-amber-50 border-amber-100' },
  binary: { label: 'Compiled Binary', icon: Cpu, color: 'text-purple-600 bg-purple-50 border-purple-100' },
  api: { label: 'API Endpoint', icon: Terminal, color: 'text-red-600 bg-red-50 border-red-100' },
  cloud_kms: { label: 'Cloud KMS', icon: KeyRound, color: 'text-slate-600 bg-slate-100 border-slate-200' },
  hardware_module: { label: 'HSM', icon: KeyRound, color: 'text-slate-600 bg-slate-100 border-slate-200' },
};

const metaFor = (sourceType) => SOURCE_META[sourceType] || { label: sourceType || 'Unknown', icon: Package, color: 'text-slate-500 bg-slate-100 border-slate-200' };

/** Best-effort human label for what was actually scanned in this job. */
const labelForGroup = (sourceType, sample) => {
  if (sourceType === 'container') {
    // Heuristic path stamps evidence_file as "image:<tag>"; prefer that if present.
    const imgHit = sample.find((a) => a.evidence_file?.startsWith('image:'));
    if (imgHit) return imgHit.evidence_file.replace(/^image:/, '');
    if (sample[0]?.evidence_file) return sample[0].evidence_file;
  }
  if (sourceType === 'binary' || sourceType === 'static-source' || sourceType === 'static_code') {
    if (sample[0]?.evidence_file) return sample[0].evidence_file;
  }
  if (sourceType === 'network_live') {
    const hosts = [...new Set(sample.map((a) => a.hostname).filter(Boolean))];
    return hosts.slice(0, 2).join(', ') + (hosts.length > 2 ? ` +${hosts.length - 2} more` : '');
  }
  return sample[0]?.hostname || 'Unnamed target';
};

const RemoveAssetsPage = () => {
  const { assets, fetchData } = useAppData();
  const toast = useToast();
  const token = sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
  const [confirming, setConfirming] = useState(null); // job_uuid pending confirmation, or 'ALL'
  const [busy, setBusy] = useState(null);

  const groups = useMemo(() => {
    const byJob = new Map();
    for (const a of assets) {
      const key = a.job_uuid || 'unknown';
      if (!byJob.has(key)) byJob.set(key, []);
      byJob.get(key).push(a);
    }
    return [...byJob.entries()]
      .map(([jobUuid, items]) => ({
        jobUuid,
        sourceType: items[0]?.source_type,
        count: items.length,
        lastScanned: items.map((a) => a.last_scanned).filter(Boolean).sort().at(-1),
        label: labelForGroup(items[0]?.source_type, items),
      }))
      .sort((a, b) => (b.lastScanned || '').localeCompare(a.lastScanned || ''));
  }, [assets]);

  const doDeleteJob = async (jobUuid) => {
    setBusy(jobUuid);
    try {
      await axios.delete(`${API_BASE}/assets/by-job/${jobUuid}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      toast.showSuccess('Target removed from inventory.');
      await fetchData();
    } catch (e) {
      toast.showError(e.response?.data?.detail || 'Failed to remove target.');
    } finally {
      setBusy(null);
      setConfirming(null);
    }
  };

  const doDeleteAll = async () => {
    setBusy('ALL');
    try {
      await axios.delete(`${API_BASE}/assets`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      toast.showSuccess('Inventory cleared.');
      await fetchData();
    } catch (e) {
      toast.showError(e.response?.data?.detail || 'Failed to clear inventory.');
    } finally {
      setBusy(null);
      setConfirming(null);
    }
  };

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Every target you have scanned, one row per scan run, across every
        scanner type. Removing a target deletes its assets, scan job, and
        CBOM history snapshot from the local database. This cannot be undone.
      </p>

      <div className="glass-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50/70 px-5 py-3">
          <span className="text-xs font-bold uppercase tracking-widest text-slate-500">
            {groups.length} target{groups.length === 1 ? '' : 's'} in inventory
          </span>

          {groups.length > 0 && (
            confirming === 'ALL' ? (
              <div className="flex items-center gap-2 text-xs">
                <span className="font-semibold text-red-600">Delete everything?</span>
                <button
                  onClick={doDeleteAll}
                  disabled={busy === 'ALL'}
                  className="flex items-center gap-1 rounded-md bg-red-600 px-2.5 py-1.5 font-bold text-white hover:bg-red-700 disabled:opacity-60"
                >
                  <Check size={12} /> Confirm
                </button>
                <button
                  onClick={() => setConfirming(null)}
                  className="flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1.5 font-semibold text-slate-500 hover:bg-slate-100"
                >
                  <X size={12} /> Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirming('ALL')}
                className="flex items-center gap-1.5 rounded-md border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-bold text-red-600 transition-colors hover:bg-red-100"
              >
                <Trash2 size={12} /> Clear all
              </button>
            )
          )}
        </div>

        {groups.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-400">
            Nothing scanned yet, run a scan from Scan Center first.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {groups.map((g) => {
              const meta = metaFor(g.sourceType);
              const Icon = meta.icon;
              return (
                <div key={g.jobUuid} className="flex items-center justify-between gap-4 px-5 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${meta.color}`}>
                      <Icon size={14} />
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-semibold text-slate-800" title={g.label}>{g.label}</div>
                      <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-400">
                        <span className="font-mono">{meta.label}</span>
                        <span>·</span>
                        <span>{g.count} asset{g.count === 1 ? '' : 's'}</span>
                        {g.lastScanned && (
                          <>
                            <span>·</span>
                            <span>{new Date(g.lastScanned).toLocaleString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {confirming === g.jobUuid ? (
                    <div className="flex shrink-0 items-center gap-2 text-xs">
                      <span className="hidden font-semibold text-red-600 sm:inline">Remove?</span>
                      <button
                        onClick={() => doDeleteJob(g.jobUuid)}
                        disabled={busy === g.jobUuid}
                        className="flex items-center gap-1 rounded-md bg-red-600 px-2.5 py-1.5 font-bold text-white hover:bg-red-700 disabled:opacity-60"
                      >
                        {busy === g.jobUuid
                          ? <span className="h-2.5 w-2.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                          : <Check size={12} />}
                        Confirm
                      </button>
                      <button
                        onClick={() => setConfirming(null)}
                        className="flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1.5 font-semibold text-slate-500 hover:bg-slate-100"
                      >
                        <X size={12} />
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirming(g.jobUuid)}
                      className="flex shrink-0 items-center gap-1.5 rounded-md border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-500 transition-colors hover:border-red-200 hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 size={12} /> Clear
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800">
        <AlertTriangle size={14} className="mt-0.5 shrink-0" />
        Removing a target deletes it permanently from the local database. It
        does not affect anything on the actual scanned system, only Q-Guardian's
        record of having scanned it.
      </div>
    </div>
  );
};

export default RemoveAssetsPage;
