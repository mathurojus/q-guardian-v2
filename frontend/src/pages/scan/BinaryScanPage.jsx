import ScannerPanel from '../../components/ScannerPanel';
import { useAppData } from '../../context/AppDataContext.jsx';

const BinaryScanPage = () => {
  const { fetchData } = useAppData();
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Parses a compiled ELF/PE/Mach-O binary with LIEF and searches its raw
        bytes for known cryptographic constant signatures (ML-KEM NTT zeta
        tables, AES S-box, MD5/SHA-1 IVs) — works even on stripped binaries.
        Click <span className="font-mono text-xs text-cobalt-700">DEMO FIXTURE</span> to
        try it against a synthetic test binary.
      </p>
      <ScannerPanel modes={['binary']} onScanComplete={fetchData} />
    </div>
  );
};

export default BinaryScanPage;
