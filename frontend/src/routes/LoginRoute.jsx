import { Navigate } from 'react-router-dom';
import LoginPage from '../components/LoginPage';
import { useAuth } from '../context/AuthContext.jsx';

const LoginRoute = () => {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Navigate to="/" replace />;
  return <LoginPage />;
};

export default LoginRoute;
