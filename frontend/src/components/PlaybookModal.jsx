import React from 'react';
import { X, ShieldAlert, Code, Zap, Clock } from 'lucide-react';

const PlaybookModal = ({ asset, playbook, onClose }) => {
  if (!asset || !playbook) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-slate-900/30 backdrop-blur-[2px] animate-in fade-in duration-300">
      <div className="glass-card w-full max-w-2xl overflow-hidden shadow-[0_32px_64px_-24px_rgba(15,23,42,0.3)] animate-in zoom-in-95 duration-300">
        <div className="border-b border-slate-200 bg-slate-50/70 p-4 flex justify-between items-center">
          <div>
            <h3 className="font-bold text-sm uppercase tracking-wider text-slate-900">Migration Playbook</h3>
            <p className="text-[10px] font-mono text-slate-400 mt-0.5">{asset.hostname}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 transition-colors">
            <X size={20} />
          </button>
        </div>
        
        <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-4">
            <InfoItem icon={<ShieldAlert size={14}/>} label="CURRENT STATE" value={playbook.current_state} />
            <InfoItem icon={<Zap size={14}/>} label="TARGET ALGORITHM" value={playbook.target_algorithm} />
            <InfoItem icon={<Code size={14}/>} label="NIST STANDARD" value={playbook.nist_standard} />
            <InfoItem icon={<Clock size={14}/>} label="EFFORT ESTIMATE" value={playbook.effort_estimate} />
          </div>

          <div className="bg-slate-50 p-4 rounded-lg border border-slate-200">
             <h4 className="text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Remediation rationale</h4>
             <p className="text-sm text-slate-700 leading-relaxed italic">
                {playbook.risk_reduction}. This migration path aligns with NSA CNSA 2.0 requirements for commercial national security systems.
             </p>
          </div>

          <div>
            <h4 className="text-[10px] font-black text-slate-900 uppercase mb-2 flex items-center gap-2 tracking-widest">
              <Code size={14} className="text-cobalt-600" /> Production-ready configuration (NGINX)
            </h4>
            <div className="bg-slate-950 rounded-lg p-4 relative group">
              <pre className="text-emerald-300 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                {playbook.config_snippet}
              </pre>
              <button 
                className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 bg-white/10 hover:bg-white/20 text-white text-[10px] px-2 py-1 rounded transition-opacity"
                onClick={() => navigator.clipboard.writeText(playbook.config_snippet)}
              >
                COPY
              </button>
            </div>
          </div>
        </div>

        <div className="border-t border-slate-200 bg-slate-50/70 p-4 flex justify-end">
          <button 
            onClick={onClose}
            className="qg-button text-xs py-2.5 px-8"
          >
            DISMISS
          </button>
        </div>
      </div>
    </div>
  );
};

const InfoItem = ({ icon, label, value }) => (
  <div className="space-y-1">
    <div className="text-[9px] font-bold text-slate-400 uppercase flex items-center gap-1 tracking-widest">
      <span className="text-cobalt-500">{icon}</span> {label}
    </div>
    <div className="text-sm font-bold text-slate-900 font-mono">{value}</div>
  </div>
);

export default PlaybookModal;
