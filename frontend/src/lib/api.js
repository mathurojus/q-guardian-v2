const trimTrailingSlash = (value) => value.replace(/\/+$/, '');

const normalizeApiPath = (value) => {
  if (!value) return '/api/v1';
  if (/^https?:\/\//i.test(value)) return trimTrailingSlash(value);
  return value.startsWith('/') ? value : `/${value}`;
};

const buildApiBase = () => {
  const rawApiBase = (import.meta.env.VITE_API_BASE || '').trim();
  const rawBackendUrl = (import.meta.env.VITE_BACKEND_URL || '').trim();

  if (/^https?:\/\//i.test(rawApiBase)) {
    return trimTrailingSlash(rawApiBase);
  }

  if (!import.meta.env.PROD && rawBackendUrl) {
    return `${trimTrailingSlash(rawBackendUrl)}${normalizeApiPath(rawApiBase)}`;
  }

  return normalizeApiPath(rawApiBase);
};

export const API_BASE = buildApiBase();
export const TOKEN_KEY = 'qguardian_token';
export const USER_KEY = 'qguardian_user';
