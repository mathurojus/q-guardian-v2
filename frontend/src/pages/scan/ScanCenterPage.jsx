import { Link } from 'react-router-dom';
import { FileCode, Package, Cpu, Terminal, Globe2, GitCompare, ArrowRight } from 'lucide-react';

const SCAN_CARDS = [
  {
    to: '/scan/source', icon: FileCode, title: 'Source Code',
    desc: 'Scan a file or directory for weak crypto API calls using AST + Semgrep.',
  },
  {
    to: '/scan/container', icon: Package, title: 'Container Image',
    desc: 'Inspect an image tag or Dockerfile for outdated crypto libraries.',
  },
  {
    to: '/scan/binary', icon: Cpu, title: 'Compiled Binary',
    desc: 'Find cryptographic constant signatures inside a compiled ELF/PE file.',
  },
  {
    to: '/scan/api', icon: Terminal, title: 'API Endpoint',
    desc: 'Probe a live URL for OWASP API Top-10 security issues.',
  },
  {
    to: '/scan/network', icon: Globe2, title: 'Network / Domain',
    desc: 'Discover subdomains and inspect live TLS configuration.',
  },
];

const ScanCenterPage = () => {
  return (
    <div className="space-y-6">
      <p className="max-w-2xl text-sm text-slate-500">
        Every scan below feeds the same asset inventory and CBOM export.
        Choose a source to start — you can run several and reconcile them
        together afterward to catch declared-vs-actual mismatches.
      </p>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {SCAN_CARDS.map((card) => (
          <Link
            key={card.to}
            to={card.to}
            className="group flex flex-col rounded-xl border border-slate-200 bg-white p-5 transition-all hover:border-cobalt-300 hover:shadow-[0_4px_20px_rgba(36,87,214,0.08)]"
          >
            <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-cobalt-50 text-cobalt-600 transition-colors group-hover:bg-cobalt-600 group-hover:text-white">
              <card.icon size={18} />
            </div>
            <h3 className="mb-1 font-bold tracking-tight text-navy">{card.title}</h3>
            <p className="mb-4 flex-1 text-[13px] leading-relaxed text-slate-500">{card.desc}</p>
            <span className="flex items-center gap-1 text-xs font-bold text-cobalt-600">
              Open scanner <ArrowRight size={13} className="transition-transform group-hover:translate-x-0.5" />
            </span>
          </Link>
        ))}

        <Link
          to="/reconcile"
          className="group flex flex-col rounded-xl border-2 border-dashed border-amber-300 bg-amber-50/40 p-5 transition-all hover:border-amber-400 hover:bg-amber-50"
        >
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-amber-100 text-amber-700 transition-colors group-hover:bg-amber-600 group-hover:text-white">
            <GitCompare size={18} />
          </div>
          <h3 className="mb-1 font-bold tracking-tight text-navy">Reconcile Sources</h3>
          <p className="mb-4 flex-1 text-[13px] leading-relaxed text-slate-500">
            Once you've run a few scans, correlate them to surface declared-vs-actual divergences.
          </p>
          <span className="flex items-center gap-1 text-xs font-bold text-amber-700">
            Run reconciliation <ArrowRight size={13} className="transition-transform group-hover:translate-x-0.5" />
          </span>
        </Link>
      </div>
    </div>
  );
};

export default ScanCenterPage;
