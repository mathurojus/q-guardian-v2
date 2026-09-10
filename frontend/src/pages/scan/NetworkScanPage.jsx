import { Link } from 'react-router-dom';
import { Activity, ShieldCheck, Search, ArrowRight, CheckCircle2 } from 'lucide-react';
import { useAppData } from '../../context/AppDataContext.jsx';

const NetworkScanPage = () => {
  const { domain, setDomain, handleScan, scanning, polling, scanProgress, scanStatusMsg } = useAppData();
  const busy = scanning || polling;
  const justCompleted = !busy && scanProgress === 100;

  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Enumerates subdomains via public certificate-transparency logs, opens a
        real TLS connection to each, and inspects the live cipher suite,
        protocol version, and certificate. Only scan domains you own or are
        authorized to test — private/internal targets are refused by default.
      </p>

      <div className="glass-card p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Target domain, e.g. example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !busy && domain && handleScan()}
              disabled={busy}
              className="w-full rounded-lg border border-slate-200 bg-slate-50 py-3 pl-9 pr-3 font-mono text-sm text-navy placeholder:font-sans placeholder:text-slate-400 transition-colors focus:border-cobalt-500 focus:bg-white focus:outline-none focus:ring-1 focus:ring-cobalt-200"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={busy || !domain}
            className="qg-button whitespace-nowrap justify-center"
          >
            {busy
              ? <><Activity size={14} className="animate-spin" /> Scanning…</>
              : <><ShieldCheck size={14} /> Trigger network scan</>}
          </button>
        </div>

        {busy && (
          <div className="mt-5">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-cobalt-600 transition-all duration-500 ease-out"
                style={{ width: `${Math.max(scanProgress || 0, 4)}%` }}
              />
            </div>
            <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span className="truncate">{scanStatusMsg || 'Initializing engines…'}</span>
              <span className="font-semibold text-cobalt-700">{Math.round(scanProgress || 0)}%</span>
            </div>
          </div>
        )}

        {justCompleted && (
          <div className="mt-5 flex items-center justify-between rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm">
            <span className="flex items-center gap-2 font-semibold text-emerald-700">
              <CheckCircle2 size={16} /> Scan complete — results added to the inventory.
            </span>
            <Link to="/inventory" className="flex items-center gap-1 text-xs font-bold text-emerald-700 hover:underline">
              View inventory <ArrowRight size={12} />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkScanPage;
