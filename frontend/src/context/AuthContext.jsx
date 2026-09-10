import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API_BASE, TOKEN_KEY, USER_KEY } from '../lib/api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken]   = useState(() => sessionStorage.getItem(TOKEN_KEY));
  const [user, setUser]     = useState(() => {
    const raw = sessionStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  });
  const [authError, setAuthError] = useState('');
  const [loggingIn, setLoggingIn] = useState(false);

  // ── Sync axios defaults and interceptors ──────────────
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }

    // On 401 response auto-logout (only if we actually had a token)
    const resInterceptor = axios.interceptors.response.use(
      (res) => res,
      (err) => {
        if (err.response?.status === 401 && sessionStorage.getItem(TOKEN_KEY)) {
          // Token expired / invalid — force logout
          _clearSession();
        }
        return Promise.reject(err);
      }
    );

    return () => {
      axios.interceptors.response.eject(resInterceptor);
    };
  }, [token]);

  function _clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
  }

  const login = useCallback(async (username, password) => {
    setLoggingIn(true);
    setAuthError('');
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, { username, password });
      const { access_token, username: returnedUser } = res.data;

      sessionStorage.setItem(TOKEN_KEY, access_token);
      const userObj = { username: returnedUser };
      sessionStorage.setItem(USER_KEY, JSON.stringify(userObj));

      setToken(access_token);
      setUser(userObj);
      return true;
    } catch (err) {
      const msg = err.response?.data?.detail || 'Login failed. Check credentials and try again.';
      setAuthError(msg);
      return false;
    } finally {
      setLoggingIn(false);
    }
  }, []);

  const logout = useCallback(() => {
    _clearSession();
  }, []);

  return (
    <AuthContext.Provider value={{ token, user, login, logout, authError, loggingIn, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
