import React, { createContext, useContext, useState } from 'react';

type User = {
  username: string;
  [k: string]: any;
};

type AuthResult = { ok: boolean; error?: string };
type AuthContextType = {
  user: User | null;
  login: (username: string, password: string) => Promise<AuthResult>;
  signup: (username: string, password: string) => Promise<AuthResult>;
  logout: () => void;
};

const STORAGE_USER = 'osrovnet_user_v1';
const STORAGE_TOKEN = 'osrovnet_token_v1';
const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000/api';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Initialize user synchronously from localStorage so consumers render
  // correctly without requiring a full page reload.
  const [user, setUser] = useState<User | null>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_USER);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  });

  const fetchUser = async (token: string) => {
    try {
      const res = await fetch(`${API_BASE}/auth/user/`, {
        headers: { Authorization: `Token ${token}` },
        credentials: 'include',
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data;
    } catch (e) {
      return null;
    }
  };

  const login = async (username: string, password: string): Promise<{ ok: boolean; error?: string } > => {
    try {
      const res = await fetch(`${API_BASE}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'include',
      });
      const text = await res.text();
      let data: any = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = { detail: text }; }
      if (!res.ok) {
        // extract message
        const msg = data?.detail || data?.message || data?.non_field_errors?.[0] || JSON.stringify(data) || 'Login failed';
        return { ok: false, error: String(msg) };
      }
      const token = data.token || data.auth_token || data.key || data.access || data.access_token;
      if (!token) return { ok: false, error: 'No token returned' };
      localStorage.setItem(STORAGE_TOKEN, token);
      // fetch user
      const u = await fetchUser(token);
      const userData = u || { username };
      localStorage.setItem(STORAGE_USER, JSON.stringify(userData));
      setUser(userData);
      return { ok: true };
    } catch (e: any) {
      return { ok: false, error: e?.message || 'Login error' };
    }
  };

  const signup = async (username: string, password: string): Promise<{ ok: boolean; error?: string }> => {
    try {
      const tryUrls = ['/auth/register/', '/auth/signup/', '/auth/users/'];
      for (const p of tryUrls) {
        try {
          const res = await fetch(`${API_BASE}${p}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include',
          });
          const text = await res.text();
          let data: any = null;
          try { data = text ? JSON.parse(text) : null; } catch (e) { data = { detail: text }; }
          if (res.status === 201 || res.status === 200) {
            // Auto-login after successful signup to provide a smooth UX.
            const loginResult = await login(username, password);
            // If login succeeded, return that result (ok: true). Otherwise surface login error.
            return loginResult.ok ? { ok: true } : { ok: false, error: loginResult.error || 'Signup created but login failed' };
          }
          // if server responded with error payload, return it
          const msg = data?.detail || data?.message || data?.non_field_errors?.[0] || JSON.stringify(data);
          return { ok: false, error: String(msg || 'Signup failed') };
        } catch (e: any) {
          // try next endpoint
        }
      }
    } catch (e) {
      // ignore
    }
    return { ok: false, error: 'Signup failed' };
  };

  const logout = () => {
    (async () => {
      try {
        const token = localStorage.getItem(STORAGE_TOKEN);
        await fetch(`${API_BASE}/auth/logout/`, {
          method: 'POST',
          headers: token ? { Authorization: `Token ${token}` } : {},
          credentials: 'include',
        });
      } catch (e) {
        // ignore server logout errors
      }
      try {
        localStorage.removeItem(STORAGE_TOKEN);
        localStorage.removeItem(STORAGE_USER);
      } catch (e) {}
      setUser(null);
    })();
  };

  return (
    <AuthContext.Provider value={{ user, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
