/**
 * Landing page. One screen, no scroll: an analyst who lands here should be one
 * click from the console. The punchline is the only neon on the page.
 */

import { ArrowRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchHealth } from '../api/client';
import { useAuth } from '../auth/AuthProvider';
import { BinaryRain } from '../components/BinaryRain';
import { BlueHat } from '../components/BlueHat';
import { BrandMark } from '../components/BrandMark';
import { LANDING_PUNCHLINE, PUNCHLINES } from '../copy';
import type { Health } from '../types/api';

function pickPunchline(param: string | null) {
  const asked = Number(param);
  const index = Number.isInteger(asked) && asked >= 1 && asked <= PUNCHLINES.length
    ? asked - 1
    : LANDING_PUNCHLINE;
  return PUNCHLINES[index] ?? PUNCHLINES[0];
}

function DecoyStatus() {
  const [health, setHealth] = useState<Health | null | 'down'>(null);

  useEffect(() => {
    let alive = true;
    fetchHealth()
      .then((value) => alive && setHealth(value))
      .catch(() => alive && setHealth('down'));
    return () => {
      alive = false;
    };
  }, []);

  const rows = [
    { id: 'ssh-decoy-01', label: 'SSH decoy', port: ':2222' },
    { id: 'web-decoy-01', label: 'Web decoy', port: ':8080' },
  ];

  return (
    <ul className="landing__facts">
      {rows.map((row) => {
        // Backend reachability only. A sensor's last event is attacker activity,
        // not proof the decoy is up (review F9), so it never lights a dot here.
        const tone = health === 'down' ? 'off' : 'idle';
        const title =
          health === 'down'
            ? 'Backend unreachable'
            : health === null
              ? 'Checking the backend'
              : 'Backend answering · decoy health not reported in v1.0';
        return (
          <li key={row.id} title={title}>
            <span className={`landing__dot landing__dot--${tone}`} />
            {row.label}
            <span className="landing__port">{row.port}</span>
          </li>
        );
      })}
      <li>
        <span className="landing__dot landing__dot--idle" />
        Rules explain. Analysts decide.
      </li>
    </ul>
  );
}

export function Landing() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const line = pickPunchline(params.get('p'));

  return (
    <div className="landing">
      <BinaryRain />
      <div className="landing__veil" aria-hidden="true" />

      <header className="landing__top">
        <BrandMark />
        <span className="landing__spacer" />
        {user ? (
          <Link to="/" className="btn btn--quiet">
            Console
          </Link>
        ) : (
          <Link to="/login" className="btn btn--quiet">
            Sign in
          </Link>
        )}
      </header>

      <main className="landing__hero">
        <div className="landing__copy">
          <p className="landing__eyebrow">Deception-based SOC console</p>
          <h1 className="landing__title">
            {line.lead} <span className="landing__punch">{line.highlight}</span>
          </h1>
          <p className="landing__sub">
            Decoys that no real user ever touches. Every touch becomes an event with an ID, every
            finding cites its evidence, and nothing is blocked until an analyst approves it.
          </p>
          <div className="landing__cta">
            <button
              type="button"
              className="btn btn--primary btn--lg"
              onClick={() => navigate(user ? '/' : '/login')}
            >
              Open the console <ArrowRight size={18} strokeWidth={2.2} />
            </button>
          </div>
        </div>

        <div className="landing__visual">
          <BlueHat className="bluehat--hero" spin={0.35} />
          <span className="landing__caption">Blue team console</span>
        </div>
      </main>

      <footer className="landing__foot">
        <DecoyStatus />
        <span className="landing__lab">Isolated lab · synthetic data only</span>
      </footer>
    </div>
  );
}
