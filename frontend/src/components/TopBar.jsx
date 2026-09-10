import { useLocation, Link } from 'react-router-dom';
import { Activity, LogOut, UserCircle2 } from 'lucide-react';

const PAGE_META = {
  '/': { title: 'Overview', crumb: ['Overview'] },
  '/scan': { title: 'Scan Center', crumb: ['Scan Center'] },
  '/scan/source': { title: 'Source Code Scanner', crumb: ['Scan Center', 'Source Code'] },
  '/scan/container': { title: 'Container Image Scanner', crumb: ['Scan Center', 'Container Image'] },
  '/scan/binary': { title: 'Compiled Binary Scanner', crumb: ['Scan Center', 'Compiled Binary'] },
  '/scan/api': { title: 'API Endpoint Scanner', crumb: ['Scan Center', 'API Endpoint'] },
  '/scan/network': { title: 'Network / Domain Scan', crumb: ['Scan Center', 'Network / Domain'] },
  '/inventory': { title: 'Asset Inventory', crumb: ['Inventory'] },
  '/remove-assets': { title: 'Remove Assets', crumb: ['Inventory', 'Remove Assets'] },
  '/risk/hndl': { title: 'HNDL Exposure', crumb: ['Risk & Compliance', 'HNDL Exposure'] },
  '/risk/compliance': { title: 'Cert-IN Compliance Mapper', crumb: ['Risk & Compliance', 'Cert-IN Mapper'] },
  '/topology': { title: 'Dependency Graph', crumb: ['Topology'] },
  '/reports/cbom': { title: 'CBOM Export', crumb: ['Reports', 'CBOM Export'] },
  '/reconcile': { title: 'Reconcile Sources', crumb: ['Reports', 'Reconcile Sources'] },
};

const TopBar = ({ user, onLogout, scanning, polling, scanProgress, scanStatusMsg }) => {
  const location = useLocation();
  const meta = PAGE_META[location.pathname] || { title: 'Q-Guardian', crumb: [] };
  const showScanBanner = (scanning || polling) && location.pathname !== '/scan/network';

  return (
    <header className="fixed left-60 right-0 top-0 z-40 border-b border-slate-200 bg-white">
      <div className="flex h-20 items-center justify-between gap-4 px-6">
        <div className="min-w-0">
          {meta.crumb.length > 1 && (
            <div className="mb-0.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              {meta.crumb.slice(0, -1).map((c, i) => (
                <span key={i}>{c} <span className="mx-1 text-slate-300">/</span></span>
              ))}
            </div>
          )}
          <h1 className="truncate text-[17px] font-bold tracking-tight text-navy">{meta.title}</h1>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          {showScanBanner && (
            <Link
              to="/scan/network"
              className="flex items-center gap-2 rounded-lg border border-cobalt-100 bg-cobalt-50 px-3 py-1.5 text-[11px] font-semibold text-cobalt-700 transition-colors hover:bg-cobalt-100"
            >
              <Activity size={13} className="animate-spin" />
              Network scan running — {Math.round(scanProgress || 0)}%
              <span className="hidden text-cobalt-500 md:inline">· {scanStatusMsg}</span>
            </Link>
          )}

          {user && (
            <div className="flex items-center gap-2 border-l border-slate-200 pl-3">
              <span className="hidden items-center gap-1.5 text-xs font-medium text-slate-600 md:flex">
                <UserCircle2 size={16} className="text-slate-400" />
                {user.username}
              </span>
              <button
                onClick={onLogout}
                title="Log out"
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-2 text-xs font-semibold text-slate-500 transition-colors hover:border-red-200 hover:bg-red-50 hover:text-red-600"
              >
                <LogOut size={14} />
                <span className="hidden sm:inline">Log out</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default TopBar;
