/**
 * Sign-in for the SOC console.
 *
 * Provider: Supabase Auth (Google OAuth plus email and password). The backend
 * has no auth yet, so this only gates the UI; real protection needs the backend
 * to verify the Supabase JWT on every /api call. Until then, treat this as the
 * front door, not the lock.
 *
 * Configuration (frontend/.env.local, names only in .env.example):
 *   VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY   enable real sign-in
 *   VITE_AUTH_LOCAL=1                            lab sign-in on this machine while no
 *                                                provider is configured
 */

import { createClient, type Session, type SupabaseClient } from '@supabase/supabase-js';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

const SUPABASE_URL: string = import.meta.env.VITE_SUPABASE_URL ?? '';
const SUPABASE_ANON_KEY: string = import.meta.env.VITE_SUPABASE_ANON_KEY ?? '';

export const AUTH_CONFIGURED = SUPABASE_URL !== '' && SUPABASE_ANON_KEY !== '';
export const AUTH_LOCAL = !AUTH_CONFIGURED && import.meta.env.VITE_AUTH_LOCAL === '1';

const LOCAL_KEY = 'dg.localSession';

const supabase: SupabaseClient | null = AUTH_CONFIGURED
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
  : null;

export interface AnalystUser {
  email: string;
  name: string;
  /** 'local' is the lab sign-in used while no provider is configured. */
  provider: 'google' | 'email' | 'local';
}

interface AuthValue {
  ready: boolean;
  user: AnalystUser | null;
  signInWithGoogle: () => Promise<string | null>;
  signInWithPassword: (email: string, password: string) => Promise<string | null>;
  signInLocal: () => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

function userFromSession(session: Session | null): AnalystUser | null {
  const user = session?.user;
  if (!user) return null;
  const meta = user.user_metadata ?? {};
  const email = user.email ?? '';
  return {
    email,
    name: typeof meta['full_name'] === 'string' ? meta['full_name'] : email.split('@')[0] ?? 'analyst',
    provider: user.app_metadata?.['provider'] === 'google' ? 'google' : 'email',
  };
}

function readLocalSession(): AnalystUser | null {
  if (!AUTH_LOCAL) return null;
  try {
    // ?local=1 starts the lab session directly, for headless screenshots.
    if (new URLSearchParams(window.location.search).get('local') === '1') {
      window.sessionStorage.setItem(LOCAL_KEY, '1');
    }
    return window.sessionStorage.getItem(LOCAL_KEY) === '1'
      ? { email: 'analyst@lab.local', name: 'Lab analyst', provider: 'local' }
      : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(!supabase);
  const [user, setUser] = useState<AnalystUser | null>(() => readLocalSession());

  useEffect(() => {
    if (!supabase) return;
    let alive = true;
    void supabase.auth.getSession().then(({ data }) => {
      if (!alive) return;
      setUser(userFromSession(data.session));
      setReady(true);
    });
    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(userFromSession(session));
    });
    return () => {
      alive = false;
      data.subscription.unsubscribe();
    };
  }, []);

  const signInWithGoogle = useCallback(async () => {
    if (!supabase) return 'Sign-in is not configured.';
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: `${window.location.origin}/` },
    });
    return error ? error.message : null;
  }, []);

  const signInWithPassword = useCallback(async (email: string, password: string) => {
    if (!supabase) return 'Sign-in is not configured.';
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return error ? error.message : null;
  }, []);

  const signInLocal = useCallback(() => {
    if (!AUTH_LOCAL) return;
    try {
      window.sessionStorage.setItem(LOCAL_KEY, '1');
    } catch {
      // Private mode: the session lasts until reload.
    }
    setUser({ email: 'analyst@lab.local', name: 'Lab analyst', provider: 'local' });
  }, []);

  const signOut = useCallback(async () => {
    try {
      window.sessionStorage.removeItem(LOCAL_KEY);
    } catch {
      // nothing stored
    }
    if (supabase) await supabase.auth.signOut();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ ready, user, signInWithGoogle, signInWithPassword, signInLocal, signOut }),
    [ready, user, signInWithGoogle, signInWithPassword, signInLocal, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>');
  return value;
}
