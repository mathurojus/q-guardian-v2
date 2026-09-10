import React, { useState } from 'react';
import axios from 'axios';
import { Activity, ShieldCheck, AlertTriangle, CheckCircle, XCircle, Search, Terminal } from 'lucide-react';
import { useToast } from '../context/ToastContext.jsx';
import { API_BASE } from '../lib/api.js';

const ApiScanner = () => {
  const toast = useToast();
  const [apiUrl, setApiUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!apiUrl.trim()) {
      toast.showError("Please enter a valid API URL.");
      return;
    }
    
    // Basic format validation
    const urlPattern = /^[a-zA-Z0-9-._]+(:[0-9]+)?(\/.*)?$/;
    if (!urlPattern.test(apiUrl.replace(/^https?:\/\//, ''))) {
       toast.showError("Invalid URL format. Please use a format like api.example.com");
       return;
    }

    setScanning(true);
    setResult(null);
    try {
      const res = await axios.post(`${API_BASE}/scan/api`, { url: apiUrl });
      if (res.data.result.error) {
          toast.showError(res.data.result.error);
      } else {
          setResult(res.data.result);
          toast.showSuccess("API Scan completed successfully!");
      }
    } catch (err) {
      toast.showError(err.response?.data?.detail || "Failed to connect to backend scanner.");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass-card p-6">
        <div className="flex items-start gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-cobalt-600 text-white">
            <Terminal size={20} />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-bold text-sm uppercase tracking-wide text-slate-900 flex items-center gap-2">
              Targeted API Security Scanner
            </h3>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mt-0.5">
              Diagnostic tool — single API exploration
            </p>
            <p className="text-[11px] leading-relaxed text-slate-500 mt-2 bg-slate-50 border border-slate-200 p-3 rounded-md">
              <strong className="text-slate-700">Note:</strong> This tool performs deep OWASP Top 10 penetration testing against a single, specific API endpoint (e.g., api.target.com). For macroscopic enterprise discovery and cryptographic inventory, use the <strong className="text-slate-700">Multi-source Scanner</strong> tab or the domain scan in the header.
            </p>
          </div>
        </div>
        
        <div className="mt-5 flex items-center gap-3">
          <input 
            type="text" 
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            placeholder="Enter API Base URL (e.g. https://api.example.com)"
            className="flex-1 px-4 py-2.5 rounded-lg border border-slate-300 bg-white text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-cobalt-500 focus:ring-2 focus:ring-cobalt-100 text-sm font-mono"
          />
          <button 
            onClick={handleScan}
            disabled={scanning || !apiUrl}
            className="qg-button whitespace-nowrap"
          >
            {scanning ? 'SCANNING API...' : (
              <>
                <ShieldCheck size={14} /> RUN SECURITY SCAN
              </>
            )}
          </button>
        </div>
      </div>

      {!result && !scanning && (
          <div className="glass-card p-12 flex flex-col items-center justify-center text-slate-400 border-2 border-dashed border-slate-200 bg-slate-50/40">
              <Search size={48} className="text-slate-300 mb-4" />
              <h4 className="font-bold text-sm text-slate-500 mb-2">READY TO SCAN</h4>
              <p className="text-xs max-w-md text-center text-slate-400">Enter an API endpoint above to analyze it against the OWASP API Security Top 10 framework, including authentication, rate-limiting, and data exposure checks.</p>
          </div>
      )}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Score Card */}
            <div className="md:col-span-1 glass-card p-6 flex flex-col items-center justify-center border-t-4 border-cobalt-600">
                <h4 className="text-xs font-bold text-slate-900 mb-6 uppercase tracking-widest">API Security Grade</h4>
                <div className="relative flex justify-center items-center w-40 h-40 rounded-full border-8 border-slate-100 mb-4">
                    <div className="absolute inset-0 rounded-full border-8 border-cobalt-600" style={{ clipPath: `polygon(0 0, 100% 0, 100% ${result.api_risk_score}%, 0 ${result.api_risk_score}%)` }}></div>
                    <span className="text-5xl font-black text-slate-900">{result.api_risk_score}</span>
                </div>
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Score out of 100</div>
                <div className={`mt-4 px-4 py-1 text-xs font-black rounded ${result.api_risk_score > 80 ? 'bg-emerald-50 text-emerald-700' : result.api_risk_score > 50 ? 'bg-amber-50 text-amber-700' : 'bg-red-50 text-red-700'}`}>
                    {result.api_risk_score > 80 ? 'A - SECURE' : result.api_risk_score > 60 ? 'C - NEEDS IMPROVEMENT' : 'F - CRITICAL RISK'}
                </div>
            </div>

            {/* HTTP Headers */}
            <div className="md:col-span-2 glass-card p-6 border-t-4 border-cobalt-500">
                <h4 className="text-xs font-bold text-slate-900 mb-4 uppercase tracking-widest">Security Headers Scorecard</h4>
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                    {Object.entries(result.security_headers).map(([header, present]) => (
                        <div key={header} className={`p-3 rounded border flex items-center justify-between ${present ? 'border-emerald-200 bg-emerald-50/60' : 'border-red-200 bg-red-50/60'}`}>
                            <span className="text-[10px] font-bold text-slate-700 font-mono truncate mr-2">{header}</span>
                            {present ? <CheckCircle size={16} className="text-emerald-600 shrink-0"/> : <XCircle size={16} className="text-red-500 shrink-0"/>}
                        </div>
                    ))}
                </div>
                <div className="mt-6 flex items-center justify-between border-t border-slate-100 pt-4">
                     <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">CORS Policy Risk</div>
                        <div className={`text-sm font-black ${result.cors_policy.risk === 'HIGH' ? 'text-red-600' : 'text-emerald-600'}`}>
                            {result.cors_policy.allow_origin || "RESTRICTED"} 
                            {result.cors_policy.risk === 'HIGH' && " (WILDCARD DETECTED)"}
                        </div>
                     </div>
                     <div className="text-right">
                        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">TLS Enforcement</div>
                        <div className={`text-sm font-black ${result.tls_enforced ? 'text-emerald-600' : 'text-red-600'}`}>
                            {result.tls_enforced ? "ENABLED" : "MISSING"}
                        </div>
                     </div>
                </div>
            </div>

            {/* OWASP Findings */}
            <div className="md:col-span-3 glass-card p-6 border-l-4 border-red-500">
                <h4 className="text-xs font-bold text-slate-900 mb-4 uppercase tracking-widest">OWASP API Top 10 Findings</h4>
                {result.owasp_findings.length === 0 ? (
                    <div className="p-8 text-center text-slate-400 font-bold bg-slate-50 border border-slate-200 rounded">NO CRITICAL OWASP FINDINGS DETECTED</div>
                ) : (
                    <div className="space-y-3">
                        {result.owasp_findings.map((f, i) => (
                            <div key={i} className="flex gap-4 p-4 border border-slate-200 rounded-lg bg-slate-50/50 items-start">
                                <span className={`px-2 py-1 text-[10px] font-black rounded shrink-0 ${f.severity === 'CRITICAL' ? 'bg-red-600 text-white' : f.severity === 'HIGH' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}`}>
                                    {f.severity}
                                </span>
                                <div className="min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <div className="text-sm font-bold text-slate-900">{f.id} VULNERABILITY</div>
                                        {f.vector && (
                                            <span className="px-2 py-0.5 text-[9px] font-black bg-slate-900 text-cobalt-300 rounded tracking-widest uppercase font-mono">
                                                VECTOR: {f.vector}
                                            </span>
                                        )}
                                    </div>
                                    <div className="text-xs text-slate-600 mt-1 font-mono bg-white border border-slate-200 p-2 rounded">{f.detail}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="md:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="glass-card p-6">
                    <h4 className="text-xs font-bold text-slate-900 mb-4 uppercase tracking-widest">Discovered Endpoints</h4>
                    <ul className="space-y-2">
                        {result.endpoints_discovered.map((ep, i) => (
                            <li key={i} className="flex justify-between items-center text-xs border-b border-slate-100 pb-2">
                                <span className="font-mono text-cobalt-700 truncate max-w-[70%]">{ep.url}</span>
                                <span className={`font-black ${ep.status === 200 ? 'text-emerald-600' : ep.status === 401 || ep.status === 403 ? 'text-sky-600' : 'text-slate-500'}`}>HTTP {ep.status}</span>
                            </li>
                        ))}
                    </ul>
                </div>
                <div className="glass-card p-6">
                    <h4 className="text-xs font-bold text-slate-900 mb-4 uppercase tracking-widest">Information Disclosure</h4>
                    {result.info_disclosure.length === 0 ? (
                        <div className="text-xs text-slate-400 italic">No leaked server signatures detected.</div>
                    ) : (
                        <ul className="space-y-2 list-disc pl-4 text-xs text-amber-700 font-mono">
                            {result.info_disclosure.map((info, i) => <li key={i}>{info}</li>)}
                        </ul>
                    )}
                </div>
            </div>
        </div>
      )}
    </div>
  );
};

export default ApiScanner;
