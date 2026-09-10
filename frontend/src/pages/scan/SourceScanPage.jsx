import ScannerPanel from '../../components/ScannerPanel';
import { useAppData } from '../../context/AppDataContext.jsx';

const SourceScanPage = () => {
  const { fetchData } = useAppData();
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Scans a local file or directory path for weak cryptographic API calls
        (e.g. <code className="font-mono text-xs text-cobalt-700">hashlib.md5()</code>,
        legacy TLS protocols, short RSA keys) using either the native AST parser
        or the Semgrep <code className="font-mono text-xs text-cobalt-700">crypto.yml</code> ruleset.
      </p>
      <ScannerPanel modes={['ast', 'semgrep']} onScanComplete={fetchData} />
    </div>
  );
};

export default SourceScanPage;
