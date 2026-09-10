import { lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './routes/ProtectedRoute.jsx';
import LoginRoute from './routes/LoginRoute.jsx';
import AppShell from './layouts/AppShell.jsx';

const OverviewPage = lazy(() => import('./pages/OverviewPage'));
const InventoryPage = lazy(() => import('./pages/InventoryPage'));
const RemoveAssetsPage = lazy(() => import('./pages/RemoveAssetsPage'));
const TopologyPage = lazy(() => import('./pages/TopologyPage'));
const ReconcilePage = lazy(() => import('./pages/ReconcilePage'));
const HndlPage = lazy(() => import('./pages/risk/HndlPage'));
const CompliancePage = lazy(() => import('./pages/risk/CompliancePage'));
const CbomPage = lazy(() => import('./pages/reports/CbomPage'));
const ScanCenterPage = lazy(() => import('./pages/scan/ScanCenterPage'));
const SourceScanPage = lazy(() => import('./pages/scan/SourceScanPage'));
const ContainerScanPage = lazy(() => import('./pages/scan/ContainerScanPage'));
const BinaryScanPage = lazy(() => import('./pages/scan/BinaryScanPage'));
const ApiScanPage = lazy(() => import('./pages/scan/ApiScanPage'));
const NetworkScanPage = lazy(() => import('./pages/scan/NetworkScanPage'));

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginRoute />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route path="/" element={<OverviewPage />} />

          <Route path="/scan" element={<ScanCenterPage />} />
          <Route path="/scan/source" element={<SourceScanPage />} />
          <Route path="/scan/container" element={<ContainerScanPage />} />
          <Route path="/scan/binary" element={<BinaryScanPage />} />
          <Route path="/scan/api" element={<ApiScanPage />} />
          <Route path="/scan/network" element={<NetworkScanPage />} />

          <Route path="/inventory" element={<InventoryPage />} />
          <Route path="/remove-assets" element={<RemoveAssetsPage />} />

          <Route path="/risk/hndl" element={<HndlPage />} />
          <Route path="/risk/compliance" element={<CompliancePage />} />

          <Route path="/topology" element={<TopologyPage />} />

          <Route path="/reports/cbom" element={<CbomPage />} />
          <Route path="/reconcile" element={<ReconcilePage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
