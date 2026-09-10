import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { AppDataProvider } from '../context/AppDataContext.jsx';

/**
 * Gate for every authenticated route. Also mounts AppDataProvider here (not
 * higher up) so it's created once per login session and shared by the shell
 * + every page beneath it — scan progress, inventory, and the playbook modal
 * all stay in sync no matter which page is active.
 */
const ProtectedRoute = () => {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return (
    <AppDataProvider>
      <Outlet />
    </AppDataProvider>
  );
};

export default ProtectedRoute;
