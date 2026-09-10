import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, ShieldAlert } from 'lucide-react';

const HNDLSimulator = ({ assets }) => {
  const hndlAssets = (Array.isArray(assets) ? assets : []).filter(a => a?.hndl);
  
  if (hndlAssets.length === 0) {
    return (
      <div className="glass-card p-12 text-center">
        <div className="flex justify-center mb-4 text-green-600"><ShieldAlert size={48} /></div>
        <h3 className="text-slate-900 font-black text-xl mb-2">NO HNDL EXPOSURE DETECTED</h3>
        <p className="text-slate-500 text-sm">All discovered assets utilize Perfect Forward Secrecy (PFS), mitigating Harvest-Now-Decrypt-Later threats.</p>
      </div>
    );
  }

  // Illustrative ramp only — NOT a per-year model. The backend's HNDL score is a
  // single point-in-time estimate; these multipliers just visualize "exposure
  // compounds the longer harvested data sits unread," they are not projections
  // for a specific future year. See the grounding advisory below.
  const currentYear = new Date().getFullYear();
  const RAMP = [0, 0.2, 0.5, 1.0, 1.5, 2.2, 3.1, 4.5];
  const data = RAMP.map((mult, i) => ({
    year: currentYear - 3 + i,
    exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * mult, 0),
  }));

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 border-l-4 border-red-600">
        <h3 className="text-slate-900 font-black text-sm mb-4 flex items-center gap-2">
          <Activity size={18} className="text-red-600" /> HARVEST-NOW-DECRYPT-LATER (HNDL) — ILLUSTRATIVE EXPOSURE RAMP
        </h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="colorExposure" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="year" fontSize={10} fontWeight="bold" />
              <YAxis fontSize={10} />
              <Tooltip />
              <Area type="monotone" dataKey="exposure" stroke="#dc2626" fillOpacity={1} fill="url(#colorExposure)" strokeWidth={3} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
         {hndlAssets.slice(0, 4).map(asset => (
           <div key={asset.id} className="glass-card p-4 border-l-4 border-amber-500">
              <div className="text-[10px] font-black text-slate-400 uppercase">{asset.hostname}</div>
              <div className="flex justify-between items-end mt-2">
                <div>
                    <div className="text-2xl font-black text-slate-800">{asset.hndl.total_gb_at_risk} GB</div>
                    <div className="text-[10px] font-bold text-red-600">EST. EXPOSURE (TIER BASELINE)</div>
                </div>
                <div className="text-right">
                    <div className="text-sm font-bold text-slate-600">Score: {asset.hndl.hndl_risk_score}</div>
                    <div className="text-[10px] text-slate-400 italic">
                      Since {new Date(asset.hndl.harvest_start_date).toLocaleDateString(undefined, { month: 'short', year: 'numeric' })}
                    </div>
                </div>
              </div>
              <div className="mt-2 pt-2 border-t border-slate-100 flex items-center gap-1">
                <ShieldAlert size={10} className="text-slate-400" />
                <span className="text-[9px] text-slate-400 uppercase tracking-tighter">
                  {asset.hndl.traffic_basis || asset.hndl.methodology_note || "Illustrative tier baseline (not measured)"}
                </span>
              </div>
           </div>
         ))}
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mt-8 shadow-sm">
        <div className="flex items-center gap-2 mb-2 text-amber-700 font-black text-[10px] uppercase tracking-widest">
            <ShieldAlert size={14} /> HNDL SIMULATION GROUNDING ADVISORY
        </div>
        <p className="text-[11px] text-amber-800 leading-relaxed font-medium">
            <strong>Disclaimer:</strong> This HNDL simulation is <strong>weakly grounded</strong>. Only the CRQC arrival-probability weighting is derived from a cited model; the per-tier traffic volumes are illustrative, configurable baselines, not measured traffic or a published source. The year-by-year ramp above is an illustrative visualization of "exposure compounds over time," not a per-year forecast. In the absence of real-time traffic logs or packet-capture (PCAP) data, treat every figure here as a theoretical risk ceiling for prioritization, not a measured exfiltration volume.
        </p>
      </div>
    </div>
  );
};

export default HNDLSimulator;
