import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Radar, FileCode, Package, Cpu, Terminal, Globe2,
  Database, Clock, ShieldCheck, Boxes, FileText, GitCompare, Trash2,
} from 'lucide-react';

const NAV_SECTIONS = [
  {
    label: null,
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
    ],
  },
  {
    label: 'Scan Center',
    items: [
      { to: '/scan', label: 'Scan Center', icon: Radar, end: true },
      { to: '/scan/source', label: 'Source Code', icon: FileCode, indent: true },
      { to: '/scan/container', label: 'Container Image', icon: Package, indent: true },
      { to: '/scan/binary', label: 'Compiled Binary', icon: Cpu, indent: true },
      { to: '/scan/api', label: 'API Endpoint', icon: Terminal, indent: true },
      { to: '/scan/network', label: 'Network / Domain', icon: Globe2, indent: true },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { to: '/inventory', label: 'Asset Inventory', icon: Database },
      { to: '/remove-assets', label: 'Remove Assets', icon: Trash2 },
    ],
  },
  {
    label: 'Risk & Compliance',
    items: [
      { to: '/risk/hndl', label: 'HNDL Exposure', icon: Clock },
      { to: '/risk/compliance', label: 'Cert-IN Mapper', icon: ShieldCheck },
    ],
  },
  {
    label: 'Topology',
    items: [
      { to: '/topology', label: 'Dependency Graph', icon: Boxes },
    ],
  },
  {
    label: 'Reports',
    items: [
      { to: '/reports/cbom', label: 'CBOM Export', icon: FileText },
      { to: '/reconcile', label: 'Reconcile Sources', icon: GitCompare },
    ],
  },
];

const Sidebar = () => {
  return (
    <aside className="fixed left-0 top-0 z-50 flex h-screen w-60 flex-col bg-navy text-slate-300">
      <div className="flex h-20 items-center gap-3 border-b border-white/10 px-5">
        <img
          src="/brand/q-guardian-logo.png"
          alt="Q-Guardian"
          className="h-9 w-auto shrink-0 object-contain"
          draggable="false"
        />
        <div className="min-w-0 leading-tight">
          <div className="font-display text-[15px] tracking-wide text-white">Q-GUARDIAN</div>
          <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-400">
            v2.0 · CycloneDX 1.6
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4 scrollbar-thin">
        {NAV_SECTIONS.map((section, si) => (
          <div key={si} className={si > 0 ? 'mt-5' : ''}>
            {section.label && (
              <div className="mb-1.5 px-2.5 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
                {section.label}
              </div>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `group flex items-center gap-2.5 rounded-lg py-2 text-[12.5px] font-medium transition-colors
                     ${item.indent ? 'pl-7 pr-2.5' : 'px-2.5'}
                     ${isActive
                       ? 'border-l-2 border-gold-500 bg-white/10 text-white'
                       : 'border-l-2 border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-100'}`
                  }
                >
                  <item.icon size={item.indent ? 13 : 15} className="shrink-0 opacity-80" />
                  <span className="truncate">{item.label}</span>
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-white/10 px-4 py-3 text-[9px] font-semibold uppercase tracking-widest text-slate-500">
        Post-Quantum CBOM · Risk Audit
      </div>
    </aside>
  );
};

export default Sidebar;
