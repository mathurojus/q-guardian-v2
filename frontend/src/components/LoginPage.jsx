import React, { useState, useEffect } from 'react';
import { Lock, User, AlertCircle, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import WireframeDottedGlobe from './ui/WireframeDottedGlobe';

// Only mount the canvas globe on ≥1024px screens (it is desktop-only by design).
const useIsDesktop = () => {
  const [isDesktop, setIsDesktop] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1024px)').matches
  );
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 1024px)');
    const onChange = (e) => setIsDesktop(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return isDesktop;
};

// Masthead — logo + wordmark side by side, centered at the top of the screen.
const BrandMasthead = ({ compact }) => (
  <div className="flex flex-col items-center text-center">
    <div className="flex items-center justify-center gap-3.5">
      <img
        src="/brand/q-guardian-logo.png"
        alt="Q-Guardian logo"
        className={`object-contain drop-shadow-[0_2px_8px_rgba(11,31,58,0.22)] ${compact ? 'h-12 w-auto' : 'h-14 w-auto'}`}
        draggable="false"
      />
      <div className="text-left">
        <div className="flex items-center gap-2.5">
          <span className={`font-extrabold tracking-tight text-navy leading-none ${compact ? 'text-3xl' : 'text-3xl xl:text-4xl'}`}>
            Q-GUARDIAN
          </span>
          <span className="rounded border border-cobalt-100 bg-white px-1.5 py-0.5 font-mono text-[9px] font-semibold text-cobalt-700">
            v2.0
          </span>
        </div>
        <p className="mt-1.5 text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-400">
          Post-Quantum CBOM & Cyber Risk Platform
        </p>
      </div>
    </div>
  </div>
);

const AuthCard = ({ username, setUsername, password, setPassword, showPw, setShowPw, handleSubmit, loggingIn, authError }) => (
  <>
    {/* Login card */}
    <div className="bg-white rounded-xl border border-slate-200 shadow-[0_1px_2px_rgba(11,31,58,0.04),0_16px_40px_-24px_rgba(11,31,58,0.18)] overflow-hidden">
      <div className="flex items-center gap-3 border-b border-slate-200 px-6 py-4">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cobalt-50 text-cobalt-600">
          <Lock size={14} />
        </span>
        <div>
          <h2 className="text-[13px] font-bold tracking-wide text-navy uppercase">
            Secure authentication required
          </h2>
          <p className="text-[10px] font-medium text-slate-400">
            Authorized security analysts and compliance officers only.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="px-6 py-6 space-y-4">

        {authError && (
          <div className="flex items-start gap-3 bg-red-50 border border-red-200 rounded-lg p-3 animate-in slide-in-from-top-2 duration-300">
            <AlertCircle size={15} className="text-red-600 mt-0.5 shrink-0" />
            <p className="text-red-700 text-xs font-medium">{authError}</p>
          </div>
        )}

        <div className="space-y-1.5">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
            <User size={11} /> Username
          </label>
          <input
            id="login-username"
            type="text"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 bg-white text-slate-900 text-sm font-medium transition-colors focus:outline-none focus:border-cobalt-500 focus:ring-1 focus:ring-cobalt-200 font-mono placeholder:text-slate-400 placeholder:font-sans"
          />
        </div>

        <div className="space-y-1.5">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
            <Lock size={11} /> Password
          </label>
          <div className="relative">
            <input
              id="login-password"
              type={showPw ? 'text' : 'password'}
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              className="w-full px-3.5 py-2.5 pr-11 rounded-lg border border-slate-300 bg-white text-slate-900 text-sm font-medium transition-colors focus:outline-none focus:border-cobalt-500 focus:ring-1 focus:ring-cobalt-200 font-mono placeholder:text-slate-400 placeholder:font-sans"
            />
            <button
              type="button"
              onClick={() => setShowPw(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
            >
              {showPw ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </div>
        </div>

        <button
          id="login-submit"
          type="submit"
          disabled={loggingIn || !username || !password}
          className="w-full py-2.5 rounded-lg bg-cobalt-600 hover:bg-cobalt-700 text-white text-[13px] font-semibold tracking-wide transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loggingIn ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              AUTHENTICATING...
            </>
          ) : (
            <>
              <ShieldCheck size={15} />
              ACCESS PLATFORM
            </>
          )}
        </button>
      </form>

      <div className="px-6 pb-5">
        <div className="border-t border-slate-200 pt-3.5 flex items-center justify-between font-mono">
          <div className="text-[9px] text-slate-400 font-semibold uppercase tracking-widest">Quantum Risk Operations Console</div>
          <div className="text-[9px] text-cobalt-700 font-semibold uppercase tracking-widest">Q-GUARDIAN v2.0</div>
        </div>
      </div>
    </div>

    {/* Trial Credentials Hint */}
    <div className="mt-4 p-3 bg-white border border-slate-200 rounded-lg text-center font-mono">
      <p className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-1">Demo Credentials</p>
      <p className="text-[11px] text-slate-500 font-medium">
        User: <span className="text-slate-900 bg-slate-50 px-1.5 py-0.5 rounded border border-slate-200">qguardian_admin</span> · 
        Pass: <span className="text-slate-900 bg-slate-50 px-1.5 py-0.5 rounded border border-slate-200">QGuardian@2026</span>
      </p>
    </div>
  </>
);

const LoginPage = () => {
  const { login, loggingIn, authError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const isDesktop = useIsDesktop();

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(username, password);
  };

  const cardProps = { username, setUsername, password, setPassword, showPw, setShowPw, handleSubmit, loggingIn, authError };

  return (
    <div className="min-h-[100svh] bg-slate-50 flex flex-col items-center justify-center lg:justify-start relative overflow-hidden text-slate-700">

      {/* Quiet cobalt top glow */}
      <div className="absolute inset-x-0 top-0 h-72 bg-[radial-gradient(900px_300px_at_50%_0%,rgba(36,87,214,0.07),transparent)] pointer-events-none" />

      <div className="relative z-10 w-full max-w-[1500px] mx-auto min-h-[100svh] flex flex-col items-center px-6 py-8">

        {/* ── Brand masthead: logo + name, top center ── */}
        <div className="lg:mt-[6vh]">
          <BrandMasthead compact={!isDesktop} />
        </div>

        {/* ── Lower band: larger globe (desktop) + auth card ── */}
        <div className="w-full flex flex-col lg:flex-row items-center justify-center gap-8 lg:gap-10 xl:gap-16 mt-8 lg:mt-0 lg:flex-1 lg:min-h-0">
          {isDesktop && (
            <div className="flex items-center justify-center lg:w-[min(460px,44vw)] lg:shrink-0">
              <WireframeDottedGlobe
                width={480}
                height={480}
                className="w-full"
              />
            </div>
          )}

          <div className="w-full max-w-md lg:w-[440px] lg:max-w-md lg:shrink-0">
            <AuthCard {...cardProps} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
