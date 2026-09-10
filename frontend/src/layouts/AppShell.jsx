import { Suspense } from 'react';
import { Outlet } from 'react-router-dom';
import { Activity, Radar, TimerReset, Waypoints } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import TopBar from '../components/TopBar';
import Chatbot from '../components/Chatbot';
import PlaybookModal from '../components/PlaybookModal';
import ErrorBoundary from '../components/ErrorBoundary';
import { useAuth } from '../context/AuthContext.jsx';
import { useAppData } from '../context/AppDataContext.jsx';

const InfoTile = ({ icon, title, body }) => (
  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
    <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold text-slate-900">
      <span className="text-cobalt-600">{icon}</span>
      {title}
    </div>
    <p className="text-xs leading-relaxed text-slate-600">{body}</p>
  </div>
);

const PageLoadingPanel = () => (
  <div className="flex min-h-[60vh] items-center justify-center">
    <div className="w-full max-w-4xl glass-card overflow-hidden">
      <div className="flex items-center gap-3 border-b border-slate-200 bg-slate-50 px-6 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cobalt-50 text-cobalt-600">
          <Activity size={16} className="animate-spin" />
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight text-slate-900">Loading module…</div>
          <p className="mt-0.5 text-xs text-slate-500">Preparing this page's engines and data channels.</p>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 p-6 md:grid-cols-3">
        <InfoTile icon={<Radar size={16} />} title="Start here" body="Scan Center covers source code, containers, binaries, APIs and live domains." />
        <InfoTile icon={<TimerReset size={16} />} title="Typical runtime" body="Most scans complete in seconds; a full domain scan can take a couple of minutes." />
        <InfoTile icon={<Waypoints size={16} />} title="What's tracked" body="Asset inventory, Mosca risk states, PQC readiness, and migration playbooks." />
      </div>
    </div>
  </div>
);

const AppShell = () => {
  const { user, logout } = useAuth();
  const { scanning, polling, scanProgress, scanStatusMsg, selectedAsset, playbook, closePlaybook } = useAppData();

  return (
    <div className="min-h-screen w-full bg-slate-50">
      <Sidebar />
      <TopBar
        user={user}
        onLogout={logout}
        scanning={scanning}
        polling={polling}
        scanProgress={scanProgress}
        scanStatusMsg={scanStatusMsg}
      />

      <main className="ml-60 min-h-screen pb-16 pt-24">
        <div className="mx-auto w-full max-w-[1400px] px-6">
          <div className="w-full min-h-[60vh] animate-in fade-in slide-in-from-bottom-4 duration-500">
            <ErrorBoundary>
              <Suspense fallback={<PageLoadingPanel />}>
                <Outlet />
              </Suspense>
            </ErrorBoundary>
          </div>
        </div>
      </main>

      <Chatbot />

      <PlaybookModal asset={selectedAsset} playbook={playbook} onClose={closePlaybook} />

      <footer className="fixed bottom-0 left-60 right-0 z-30 flex justify-between border-t border-slate-200 bg-white px-6 py-2 text-[10px] font-bold uppercase tracking-widest text-slate-400">
        <div>&copy; 2026 Q-GUARDIAN QUANTUM TRANSITION INTELLIGENCE. ALL RIGHTS RESERVED.</div>
        <div className="flex gap-4">
          <span>PRIVACY POLICY</span>
          <span>DISCLAIMER</span>
          <span className="hidden sm:inline">POWERED BY MOSCA RISK COUNTDOWN ENGINE</span>
        </div>
      </footer>
    </div>
  );
};

export default AppShell;
