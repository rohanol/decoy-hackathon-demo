/**
 * Sign in. With a provider configured: Google first, email and password second.
 * Without one, on the lab machine: a single local sign-in. The page never shows
 * controls that cannot work. See auth/AuthProvider.tsx for what this protects.
 */

import { ArrowRight } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { AUTH_CONFIGURED, AUTH_LOCAL, useAuth } from '../auth/AuthProvider';
import { BinaryRain } from '../components/BinaryRain';
import { BrandMark } from '../components/BrandMark';

function GoogleLogo() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.1A6.6 6.6 0 0 1 5.49 12c0-.73.13-1.44.35-2.1V7.06H2.18A11 11 0 0 0 1 12c0 1.78.43 3.45 1.18 4.94l3.66-2.84z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1A11 11 0 0 0 2.18 7.06l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38z"
      />
    </svg>
  );
}

function ProviderSignIn() {
  const { signInWithGoogle, signInWithPassword } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (formEvent: FormEvent) => {
    formEvent.preventDefault();
    setBusy(true);
    setError(await signInWithPassword(email.trim(), password));
    setBusy(false);
  };

  return (
    <>
      <button
        type="button"
        className="btn btn--google"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          const message = await signInWithGoogle();
          if (message) {
            setError(message);
            setBusy(false);
          }
        }}
      >
        <GoogleLogo /> Continue with Google
      </button>

      <div className="auth__or">
        <span>or</span>
      </div>

      <form className="auth__form" onSubmit={submit}>
        <label className="field">
          <span className="field__label">Work email</span>
          <input
            className="input input--lg"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(changeEvent) => setEmail(changeEvent.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Password</span>
          <input
            className="input input--lg"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(changeEvent) => setPassword(changeEvent.target.value)}
          />
        </label>
        <button type="submit" className="btn btn--primary btn--block" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      {error ? (
        <p className="auth__error" role="alert">
          {error}
        </p>
      ) : null}
    </>
  );
}

export function Login() {
  const { user, signInLocal } = useAuth();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? '/';

  if (user) return <Navigate to={from} replace />;

  return (
    <div className="auth">
      <BinaryRain strength={0.6} />
      <div className="landing__veil" aria-hidden="true" />

      <header className="landing__top">
        <BrandMark />
      </header>

      <main className="auth__main">
        <section className="auth__card" aria-labelledby="signin-title">
          <h1 id="signin-title" className="auth__title">
            Sign in
          </h1>
          <p className="auth__lead">to the DeceptionGraph console</p>

          {AUTH_CONFIGURED ? (
            <ProviderSignIn />
          ) : AUTH_LOCAL ? (
            <button type="button" className="btn btn--primary btn--block btn--lg" onClick={signInLocal}>
              Enter the console <ArrowRight size={18} strokeWidth={2.2} />
            </button>
          ) : (
            <p className="auth__error" role="alert">
              Sign-in is not set up on this machine.
            </p>
          )}
        </section>
        <p className="auth__foot">Access is limited to the lab SOC team.</p>
      </main>
    </div>
  );
}
