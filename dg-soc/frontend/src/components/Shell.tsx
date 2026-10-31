/** App shell: sidebar, topbar, page transitions. DESIGN_SPEC.md section 4. */

import {
  Activity,
  LayoutGrid,
  LogOut,
  Orbit,
  Radar,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { motion } from 'motion/react';
import { useEffect, useState } from 'react';
import { NavLink, useLocation, useOutlet } from 'react-router-dom';
import { useAuth } from '../auth/AuthProvider';
import { BlueHat } from './BlueHat';
import { BrandMark } from './BrandMark';
import { ConnectionPill } from './ConnectionPill';
import { Dot } from './primitives';
import { USE_FIXTURES } from '../api/config';
import { SENSOR_LABEL } from '../copy';
import { relativeFromNow } from '../lib/format';
import { useLiveStore } from '../state/LiveStore';
import { SENSOR_IDS, type Health } from '../types/api';

/**
 * LIVE / REPLAY / FIXTURES, on every screen (PRD section 8).
 *
 * Two independent signals guard the demo path: the build-time fixture flag, and
 * capture_mode on the events themselves. Fixture events carry
 * capture_mode "replay", so even if the flag check were bypassed the chip would
 * still not read LIVE.
 */
function CaptureChip() {
  const { captureMode } = useLiveStore();

  if (USE_FIXTURES) {
    return (
      <span
        className="pill pill--warn"
        title="Fixture data from contracts/examples/events_p3.json. Not a live capture."
      >
        FIXTURES
      </span>
    );
  }
  if (captureMode === 'replay') {
    return (
      <span className="pill pill--pending" title="Replayed capture, not live sensor traffic">
        REPLAY
      </span>
    );
  }
  if (captureMode === null) {
    // No events yet, so there is no capture to describe. Claiming LIVE here
    // would be a claim we cannot back (DESIGN_SPEC.md law 3).
    return (
      <span className="pill" title="No events received yet, so there is no capture mode to report">
        NO DATA
      </span>
    );
  }
  return (
    <span className="pill pill--ok" title="Live sensor traffic">
      LIVE
    </span>
  );
}

function UtcClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <span className="topbar__clock" title="All timestamps in this app are UTC">
      {now.toISOString().slice(11, 19)} UTC
    </span>
  );
}

export type SensorTone = 'ok' | 'warn' | 'danger' | 'neutral';

/** Health of one sensor from GET /api/health, shared by the sidebar and the Sensors page. */
export function sensorState(
  health: Health | null,
  sensorId: string,
  now: Date,
): { tone: SensorTone; text: string; lastSeen: string | null } {
  if (health === null) return { tone: 'danger', text: 'unreachable', lastSeen: null };
  const lastSeen = health.sensors[sensorId] ?? null;
  if (lastSeen === null) return { tone: 'neutral', text: 'no events yet', lastSeen };
  const ageSeconds = Math.max(0, (now.getTime() - new Date(lastSeen).getTime()) / 1000);
  const tone = ageSeconds < 60 ? 'ok' : ageSeconds < 300 ? 'warn' : 'neutral';
  return {
    tone,
    text: `${tone === 'warn' ? 'stale · ' : ''}${relativeFromNow(lastSeen, now)}`,
    lastSeen,
  };
}

/**
 * The cheapest insurance in the build: when the demo misbehaves this says
 * instantly whether the problem is the decoy, the backend or the UI. In the
 * sidebar it is one dot per sensor on the Sensors nav item.
 */
function SensorDots() {
  const { health } = useLiveStore();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <span className="navitem__dots">
      {SENSOR_IDS.map((sensorId) => {
        const state = sensorState(health, sensorId, now);
        return (
          <span key={sensorId} title={`${SENSOR_LABEL[sensorId] ?? sensorId}: ${state.text}`}>
            <Dot tone={state.tone} />
          </span>
        );
      })}
    </span>
  );
}

const NAV = [
  { to: '/', label: 'Overview', end: true, icon: LayoutGrid },
  { to: '/events', label: 'Live Feed', end: false, icon: Activity },
  { to: '/incidents', label: 'Incidents', end: false, icon: ShieldAlert },
  { to: '/graph', label: 'ChakraView', end: false, icon: Orbit },
  { to: '/response', label: 'Response', end: false, icon: ShieldCheck },
  { to: '/sensors', label: 'Sensors', end: false, icon: Radar },
] as const;

/** Enter animation per section; query-string changes do not replay it. */
function AnimatedOutlet() {
  const location = useLocation();
  const outlet = useOutlet();
  const section = location.pathname.split('/')[1] ?? '';
  return (
    <motion.div
      key={section}
      className="main__page"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
    >
      {outlet}
    </motion.div>
  );
}

export function Shell() {
  const { labRunId, receivedCount } = useLiveStore();
  const { user, signOut } = useAuth();

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Console">
        <div className="sidebar__brand">
          <BrandMark to="/" />
        </div>

        <div className="sidebar__nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? 'navitem navitem--active' : 'navitem')}
            >
              <item.icon className="navitem__icon" size={18} strokeWidth={1.9} />
              <span>{item.label}</span>
              {item.to === '/events' && receivedCount > 0 ? (
                <span className="navitem__count">{receivedCount}</span>
              ) : null}
              {item.to === '/sensors' ? <SensorDots /> : null}
            </NavLink>
          ))}
        </div>

        <div className="sidebar__team">
          <BlueHat className="bluehat--side" spin={0.5} />
          <div className="sidebar__who">
            <span className="sidebar__team-title">Blue team</span>
            <span className="sidebar__team-user" title={user?.email}>
              {user?.name ?? 'analyst'}
              {user?.provider === 'dev' ? ' · dev' : ''}
            </span>
          </div>
          <button
            type="button"
            className="iconbtn"
            title="Sign out"
            aria-label="Sign out"
            onClick={() => void signOut()}
          >
            <LogOut size={16} />
          </button>
        </div>
      </nav>

      <header className="topbar">
        <CaptureChip />
        <span className="topbar__spacer" />
        {labRunId ? (
          <span className="topbar__run" title="lab_run_id">
            {labRunId}
          </span>
        ) : null}
        <ConnectionPill />
        <UtcClock />
      </header>

      <main className="main">
        <AnimatedOutlet />
      </main>
    </div>
  );
}
