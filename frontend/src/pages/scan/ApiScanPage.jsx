import ApiScanner from '../../components/ApiScanner';

const ApiScanPage = () => (
  <div className="space-y-4">
    <p className="max-w-2xl text-sm text-slate-500">
      Probes a live API URL for OWASP API Top-10 issues (missing auth,
      exposed specs, rate limiting, TLS misconfiguration). Read-only checks
      run by default — destructive probes stay off unless explicitly enabled
      on the backend.
    </p>
    <ApiScanner />
  </div>
);

export default ApiScanPage;
