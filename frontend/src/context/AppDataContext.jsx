import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API_BASE } from '../lib/api.js';
import { useAuth } from './AuthContext.jsx';
import { useToast } from './ToastContext.jsx';

const AppDataContext = createContext(null);

/**
 * Cross-page application state: the asset inventory + rating (shared by
 * Overview/Inventory/Risk/Topology/Reports pages), the background network
 * scan job (so its progress is visible from anywhere, not just the page that
 * started it), and the migration-playbook modal (opened from Inventory).
 */
export function AppDataProvider({ children }) {
  const { token, isAuthenticated } = useAuth();
  const toast = useToast();

  const [assets, setAssets] = useState([]);
  const [rating, setRating] = useState(null);

  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [polling, setPolling] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatusMsg, setScanStatusMsg] = useState('');

  const [selectedAsset, setSelectedAsset] = useState(null);
  const [playbook, setPlaybook] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};
      const [assetsRes, ratingRes] = await Promise.all([
        axios.get(`${API_BASE}/assets`, { headers: authHeaders }),
        axios.get(`${API_BASE}/enterprise/rating`, { headers: authHeaders }),
      ]);
      setAssets(Array.isArray(assetsRes.data) ? assetsRes.data : []);
      setRating(ratingRes.data && typeof ratingRes.data === 'object' ? ratingRes.data : null);
    } catch (err) {
      console.error('Error fetching data:', err);
      setAssets([]);
      setRating(null);
    }
  }, [token]);

  const handleScan = useCallback(async (targetDomain) => {
    const finalDomain = (targetDomain ?? domain).trim();
    if (!finalDomain) return;
    setScanning(true);
    setPolling(false);
    setScanProgress(0);
    setScanStatusMsg('Initializing…');
    try {
      const res = await axios.post(`${API_BASE}/scan/trigger`, { domain: finalDomain }, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const jobId = res.data.job_id;

      setPolling(true);
      let pollDelay = 1000;
      let active = true;

      const poll = async () => {
        if (!active) return;
        try {
          const statusRes = await axios.get(`${API_BASE}/scan/${jobId}/status`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {},
          });
          const data = statusRes.data;
          setScanProgress(data.progress || 0);
          setScanStatusMsg(data.current_step || 'Processing…');

          if (data.status === 'COMPLETED') {
            active = false;
            setPolling(false);
            setScanning(false);
            setScanProgress(100);
            setScanStatusMsg('Finalizing…');
            setTimeout(fetchData, 800);
            return;
          } else if (data.status === 'FAILED') {
            active = false;
            setPolling(false);
            setScanning(false);
            toast.showError('Scan failed: ' + data.current_step);
            setScanStatusMsg('');
            return;
          }
          if (pollDelay < 3000) pollDelay += 500;
          setTimeout(poll, pollDelay);
        } catch (e) {
          console.error('Polling error', e);
          setTimeout(poll, 1000);
        }
      };
      setTimeout(poll, pollDelay);
    } catch (err) {
      toast.showError('Scan failed. Ensure backend is running.');
      setScanning(false);
    }
  }, [domain, token, toast, fetchData]);

  const handleOpenPlaybook = useCallback(async (asset) => {
    setSelectedAsset(asset);
    try {
      const res = await axios.get(`${API_BASE}/migration/${asset.id}/playbook`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      setPlaybook(res.data);
    } catch (err) {
      console.error('Failed to fetch playbook');
    }
  }, [token]);

  const closePlaybook = useCallback(() => {
    setSelectedAsset(null);
    setPlaybook(null);
  }, []);

  useEffect(() => {
    if (isAuthenticated) fetchData();
  }, [isAuthenticated, fetchData]);

  const value = {
    assets, rating, fetchData,
    domain, setDomain, handleScan, scanning, polling, scanProgress, scanStatusMsg,
    selectedAsset, playbook, handleOpenPlaybook, closePlaybook,
  };

  return <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>;
}

export function useAppData() {
  const ctx = useContext(AppDataContext);
  if (!ctx) throw new Error('useAppData must be used inside <AppDataProvider>');
  return ctx;
}
