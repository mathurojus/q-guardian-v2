import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { ShieldCheck, Clock, AlertTriangle, FileText, Activity, Database, CheckCircle2, Radar, TimerReset, Waypoints, ArrowRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { API_BASE } from '../lib/api.js';

const RISK_HEX = {
  stable:   '#168A68',
  warning:  '#D99000',
  critical: '#D92D20',
  pqc:      '#2457D6',
};

const Dashboard = ({ assets, rating }) => {
  const [intel, setIntel] = useState([]);
  const safeAssets = Array.isArray(assets) ? assets : [];
  const safeRating = rating && typeof rating === 'object'
    ? rating
    : { score: 0, status: 'N/A', asset_count: 0 };

  useEffect(() => {
    axios.get(`${API_BASE}/threat-intel`)
      .then(res => setIntel(Array.isArray(res.data) ? res.data : []))
      .catch(err => console.error("Failed to fetch threat intel", err));
  }, []);

  if (!rating && safeAssets.length === 0) return <AnalystWarmupPanel />;

  if (safeAssets.length === 0) {
    return (
      <div className="glass-card flex min-h-[50vh] flex-col items-center justify-center border-2 border-dashed border-slate-200 text-center animate-in zoom-in-95 duration-500">
        <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-lg border border-slate-200 bg-slate-50">
          <ShieldCheck size={26} className="text-cobalt-600" />
        </div>
        <h2 className="text-lg font-bold tracking-tight text-navy">Platform ready</h2>
        <p className="mb-6 mt-1.5 max-w-lg text-[13px] text-slate-500">
          There are no scanned assets in the inventory yet. Run your first scan — source
          code, a container image, a compiled binary, or a live domain — to begin
          post-quantum risk analysis.
        </p>
        <Link
          to="/scan"
          className="inline-flex items-center gap-2 rounded-lg bg-cobalt-600 px-5 py-2.5 text-[12px] font-bold text-white transition-colors hover:bg-cobalt-700"
        >
          Go to Scan Center <ArrowRight size={14} />
        </Link>
      </div>
    );
  }

  const handleDownloadBrief = () => {
    window.location.href = `${API_BASE}/reports/board-brief`;
  };

  const pqcReadyCount = safeAssets.filter(a => a?.is_pqc).length;
  const criticalCount = safeAssets.filter(a => a?.mosca?.risk_state === 'CRITICAL').length;
  const warningCount = safeAssets.filter(a => a?.mosca?.risk_state === 'WARNING').length;
  const stableCount = safeAssets.filter(a => !a?.mosca || !['CRITICAL', 'WARNING'].includes(a.mosca.risk_state)).length;

  const data = [
    { name: 'Stable', value: stableCount, color: RISK_HEX.stable },
    { name: 'Warning', value: warningCount, color: RISK_HEX.warning },
    { name: 'Critical', value: criticalCount, color: RISK_HEX.critical },
    { name: 'PQC Ready', value: pqcReadyCount, color: RISK_HEX.pqc },
  ];

  const statusTone =
    safeRating.score > 700 ? { pill: 'bg-success/10 text-success' }
      : safeRating.score > 400 ? { pill: 'bg-cobalt-50 text-cobalt-700' }
      : { pill: 'bg-red-50 text-red-700' };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="grid grid-cols-1 gap-4 md:grid-cols-3"
    >
      {/* Enterprise rating */}
      <motion.div
        whileHover={{ translateY: -1 }}
        className="panel-elevated flex flex-col items-center justify-center p-7 text-center"
      >
        <div className="mb-5 flex flex-col items-center">
          <span className="mb-2 inline-flex h-1 w-7 rounded-full bg-gold" />
          <div className="qg-label">Enterprise cyber rating</div>
        </div>
        <div className="font-mono text-7xl font-bold tracking-tight text-navy">
          {safeRating.score}
        </div>
        <span className={`qg-chip mt-3 border border-slate-200 ${statusTone.pill}`}>
          {safeRating.status}
        </span>
        <button onClick={handleDownloadBrief} className="qg-button-ghost mt-6">
          <FileText size={13} /> Export board brief
        </button>
      </motion.div>

      {/* Risk distribution */}
      <div className="panel-elevated md:col-span-2 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="qg-heading">Assets by Mosca risk state</h3>
          <span className="qg-label">{safeAssets.length} assets</span>
        </div>
        <div className="h-52">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data.filter(d => d.value > 0)} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#667085' }} axisLine={{ stroke: '#E1E6ED' }} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#98A2B3' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                cursor={{ fill: 'rgba(11,31,58,0.04)' }}
                contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #E1E6ED', borderRadius: 8, fontSize: 12, color: '#0B1F3A', boxShadow: '0 8px 20px -12px rgba(11,31,58,0.25)' }}
                labelStyle={{ color: '#344054', fontWeight: 600 }}
                itemStyle={{ color: '#0B1F3A' }}
              />
              <Bar dataKey="value" radius={[2, 2, 0, 0]} maxBarSize={44}>
                {data.filter(d => d.value > 0).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Stat strip */}
      <div className="md:col-span-3 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard title="Total assets" value={safeAssets.length} icon={<Database size={17} />} color="#0B1F3A" />
        <StatCard title="Stable" value={stableCount} icon={<CheckCircle2 size={17} />} color={RISK_HEX.stable} />
        <StatCard title="Critical risks" value={criticalCount} icon={<AlertTriangle size={17} />} color={RISK_HEX.critical} />
        <StatCard title="Mosca warnings" value={warningCount} icon={<Clock size={17} />} color={RISK_HEX.warning} />
      </div>

      {/* Threat feed */}
      <div className="glass-card md:col-span-3 overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
          <h3 className="qg-heading flex items-center gap-2">
            <Activity size={14} className="text-cobalt-600" /> Threat intelligence feed
          </h3>
          <span className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-widest text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-success qg-live-dot" /> Live
          </span>
        </div>
        {intel.length === 0 ? (
          <p className="py-8 text-center font-mono text-xs text-slate-400">No intelligence items available.</p>
        ) : (
          <div className="divide-y divide-slate-100">
            {intel.map((item, idx) => (
              <IntelItem key={idx} {...item} />
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
};

const IntelItem = ({ date, source, title, relevance, sample }) => (
  <div className="flex items-start gap-3 px-5 py-3 transition-colors hover:bg-slate-50">
    <span className="mt-0.5 inline-flex h-1.5 w-1.5 shrink-0 rounded-full bg-cobalt-300" />
    <div className="min-w-0 flex-1">
      <div className="text-[13px] font-medium leading-snug text-slate-800">
        {title}
        {sample && (
          <span className="ml-2 rounded border border-amber-200 bg-amber-50 px-1 py-0.5 text-[9px] font-bold uppercase tracking-wide text-amber-700">
            sample
          </span>
        )}
      </div>
      <div className="mt-0.5 text-[11px] text-slate-400">Relevance: {relevance}</div>
    </div>
    <div className="flex shrink-0 flex-col items-end gap-1">
      <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-slate-500">
        {source}
      </span>
      <span className="font-mono text-[9px] text-slate-400">{date}</span>
    </div>
  </div>
);

const AnalystWarmupPanel = () => (
  <div className="flex min-h-[55vh] items-center justify-center">
    <div className="w-full max-w-3xl">
      <div className="panel-elevated overflow-hidden">
        <div className="flex items-center gap-3 border-b border-slate-200 bg-slate-50 px-6 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cobalt-50 text-cobalt-600">
            <Activity size={15} />
          </div>
          <div>
            <div className="text-sm font-bold text-navy">Initializing analyst workspace</div>
            <p className="text-xs text-slate-500">
              Establishing secure data channels and loading multi-source posture.
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-4 p-5 md:grid-cols-3">
          <InfoTile icon={<Radar size={15} />} title="Start here" body="Use TRIGGER NETWORK SCAN to assess a domain, or the Multi-Source scanner for repos, containers and binaries." />
          <InfoTile icon={<TimerReset size={15} />} title="Typical runtime" body="Full scans usually complete in 2–5 minutes depending on discovery depth and endpoint latency." />
          <InfoTile icon={<Waypoints size={15} />} title="What loads" body="Asset inventory, Mosca risk states, PQC readiness, threat intelligence and migration playbooks." />
        </div>
      </div>
    </div>
  </div>
);

const InfoTile = ({ icon, title, body }) => (
  <div className="rounded-lg border border-slate-200 bg-white p-4">
    <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold text-navy">
      <span className="text-cobalt-600">{icon}</span>
      {title}
    </div>
    <p className="text-xs leading-relaxed text-slate-500">{body}</p>
  </div>
);

const StatCard = ({ title, value, icon, color }) => (
  <div className="glass-card flex items-center gap-3.5 px-5 py-4">
    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-slate-50" style={{ color }}>
      {icon}
    </div>
    <div className="min-w-0">
      <div className="qg-label">{title}</div>
      <div className="font-mono text-2xl font-bold text-navy">{value}</div>
    </div>
  </div>
);

export default Dashboard;
