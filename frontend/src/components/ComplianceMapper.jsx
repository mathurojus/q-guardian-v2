import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Landmark, Clock3, Flag, ExternalLink, ChevronRight, ShieldCheck } from 'lucide-react';
import { API_BASE } from '../lib/api.js';

const FRAMEWORK_META = {
  rbi_csf_2: {
    label: 'RBI Baseline Cyber Security Controls',
    sub: 'Cryptographic control violations (DBS.CO/CSITE/BC.11/33.01.001/2015-16, Annex-1; Digital Payment Security Controls, 2021)',
    icon: <Landmark size={16} />,
    accent: 'border-red-500',
    empty: 'No RBI baseline control violations detected in the current CBOM.',
  },
  nist_ir_8547: {
    label: 'NIST IR 8547 — PQC transition',
    sub: 'Deprecate 112-bit quantum-vulnerable algorithms after 2030 · disallow after 2035',
    icon: <Clock3 size={16} />,
    accent: 'border-cobalt-500',
    empty: 'No quantum-vulnerable assets — inventory is tracking the NIST IR 8547 timeline.',
  },
  india_dst_tec: {
    label: 'India — DST National Quantum Mission + TEC QSC',
    sub: 'NQM 2023–2031 horizon and supply-chain review flags',
    icon: <Flag size={16} />,
    accent: 'border-emerald-500',
    empty: 'No India DST/TEC quantum-readiness flags in the current CBOM.',
  },
};

const StateChip = ({ state }) => {
  const cfg = {
    'AT-RISK': 'bg-red-50 text-red-700 border-red-200',
    OPEN: 'bg-amber-50 text-amber-700 border-amber-200',
    TRACK: 'bg-cobalt-50 text-cobalt-700 border-cobalt-100',
  }[state] || 'bg-slate-100 text-slate-500 border-slate-200';
  return (
    <span className={`qg-chip border ${cfg}`}>
      {state.toLowerCase()}
    </span>
  );
};

const FindingCard = ({ finding, accent }) => (
  <div className={`flex gap-4 border-l-2 ${accent} pl-4 py-1`}>
    <div className="min-w-0 flex-1">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-[11px] font-bold text-cobalt-700">{finding.control}</div>
        {finding.risk_state && (
          <span className="qg-chip border border-slate-200 text-slate-500">
            mosca: {finding.risk_state.toLowerCase()}
          </span>
        )}
      </div>
      <div className="mt-1 text-sm font-medium text-slate-800">{finding.description}</div>
      <div className="mt-1 text-[11px] italic text-slate-500">
        Remediation: {finding.remediation}
      </div>

      {finding.timeline_flags?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {finding.timeline_flags.map((tf, tIdx) => (
            <span
              key={tIdx}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2 py-1 font-mono text-[10px] text-slate-600"
              title={`${tf.milestone} — ${tf.deadline}`}
            >
              <Clock3 size={10} className="text-cobalt-500" />
              <span>{tf.milestone}</span>
              <span className="text-slate-400">· by {tf.deadline}</span>
              <StateChip state={tf.state} />
            </span>
          ))}
        </div>
      )}
    </div>
    <button className="self-center text-slate-300 transition-colors hover:text-slate-500">
      <ExternalLink size={13} />
    </button>
  </div>
);

const ComplianceMapper = () => {
  const [frameworks, setFrameworks] = useState(null);
  const [summary, setSummary] = useState({});

  useEffect(() => {
    axios.get(`${API_BASE}/compliance/frameworks`)
      .then(res => {
        setFrameworks(res.data?.frameworks || {});
        setSummary(res.data?.summary || {});
      })
      .catch(err => {
        console.error(err);
        axios.get(`${API_BASE}/compliance/rbi`)
          .then(res => {
            setFrameworks({ rbi_csf_2: res.data });
            setSummary({ rbi_csf_2: res.data.length });
          })
          .catch(e => console.error(e));
      });
  }, []);

  const total = Object.values(summary).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);

  return (
    <div className="space-y-5">
      {/* Master header */}
      <div className="panel-elevated flex flex-wrap items-center justify-between gap-4 p-5">
        <div>
          <h3 className="qg-heading flex items-center gap-2">
            <ShieldCheck size={16} className="text-cobalt-600" />
            Cross-framework regulatory mapper
          </h3>
          <p className="mt-0.5 text-[11px] text-slate-500">
            RBI baseline cyber controls · NIST IR 8547 (PQC transition) · India DST/TEC (National Quantum Mission)
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="qg-chip border border-slate-200 text-slate-600">RBI {summary.rbi_csf_2 ?? 0}</span>
          <span className="qg-chip border border-cobalt-100 bg-cobalt-50 text-cobalt-700">NIST 8547 {summary.nist_ir_8547 ?? 0}</span>
          <span className="qg-chip border border-emerald-200 bg-emerald-50 text-emerald-700">India {summary.india_dst_tec ?? 0}</span>
        </div>
      </div>

      {!frameworks ? (
        <div className="glass-card p-12 text-center text-sm text-slate-400">Loading regulatory mappings…</div>
      ) : (
        Object.entries(FRAMEWORK_META).map(([key, meta]) => {
          const rows = frameworks[key] || [];
          return (
            <div key={key} className="glass-card overflow-hidden">
              <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/70 px-5 py-4">
                <div>
                  <div className="flex items-center gap-2 text-[13px] font-semibold text-slate-900">
                    <span className="text-cobalt-600">{meta.icon}</span>
                    {meta.label}
                  </div>
                  <div className="qg-label mt-0.5">{meta.sub}</div>
                </div>
                <span className={`qg-chip shrink-0 border ${rows.length ? 'border-red-200 bg-red-50 text-red-700' : 'border-slate-200 text-slate-400'}`}>
                  {rows.length} {rows.length === 1 ? 'asset' : 'assets'} flagged
                </span>
              </div>

              <div className="space-y-3 p-5">
                {rows.length === 0 ? (
                  <div className="py-4 text-center text-sm text-slate-400">{meta.empty}</div>
                ) : (
                  rows.map((item, idx) => (
                    <div key={idx} className="rounded-lg border border-slate-200 bg-white">
                      <div className="flex items-center justify-between gap-2 border-b border-slate-100 bg-slate-50/50 px-4 py-2.5">
                        <span className="flex min-w-0 items-center gap-1.5 font-mono text-[11px] font-medium text-slate-700">
                          <ChevronRight size={12} className="shrink-0 text-slate-300" />
                          <span className="truncate">{item.hostname}</span>
                          {key !== 'rbi_csf_2' && (
                            <span className="qg-chip shrink-0 border border-slate-200 text-slate-500">
                              {item.source_type} · {item.algorithm}
                            </span>
                          )}
                        </span>
                        <span className="qg-label shrink-0">
                          {item.findings.length} violation{item.findings.length === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="space-y-4 p-4">
                        {item.findings.map((finding, fIdx) => (
                          <FindingCard key={fIdx} finding={finding} accent={meta.accent} />
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })
      )}
    </div>
  );
};

export default ComplianceMapper;
