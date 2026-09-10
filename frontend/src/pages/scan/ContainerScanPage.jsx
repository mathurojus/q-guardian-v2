import ScannerPanel from '../../components/ScannerPanel';
import { useAppData } from '../../context/AppDataContext.jsx';

const ContainerScanPage = () => {
  const { fetchData } = useAppData();
  return (
    <div className="space-y-4">
      <p className="max-w-2xl text-sm text-slate-500">
        Scans a container image tag or local Dockerfile for outdated crypto
        libraries (OpenSSL, cryptography, BouncyCastle, …). Uses Trivy/Syft
        when installed; otherwise falls back to a tag-based estimate, and
        every finding is labeled with how it was obtained.
      </p>
      <ScannerPanel modes={['container']} onScanComplete={fetchData} />
    </div>
  );
};

export default ContainerScanPage;
