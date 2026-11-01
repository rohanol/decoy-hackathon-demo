/**
 * The fiction manifest: every lure the lab plants, where it sits in the wheel,
 * and how an event is placed on it.
 *
 * ChakraView draws the LIE we told, not the attack. Each lure is a place in
 * the fiction. Radius is depth into it (perimeter outside, the crown jewel at
 * the centre); the left half is the SSH decoy, the right half the web decoy.
 *
 * This file is a mirror of decisions made elsewhere, so every entry names its
 * source. If a decoy changes, change it here too:
 *   - config/honeytokens.yaml          token ids, where planted, where valid
 *   - config/web_patterns.yaml         hidden_paths
 *   - deployment/cowrie/honeyfs/...    notes.txt
 *   - decoys/web/app.py                /login, /search, /download, /.env
 *
 * classify() only answers "which place in the fiction did this event reach?".
 * It never decides whether something was an attack: that is the backend's job,
 * and the wheel shows it by citing findings (DESIGN_SPEC.md law 1).
 */

import type { SocEvent } from '../types/api';

export type Sector = 'ssh' | 'web' | 'core';
export type RingId = 'perimeter' | 'probe' | 'foothold' | 'deep' | 'crown';

export interface Ring {
  id: RingId;
  label: string;
  /** Radius in wheel units (the SVG is 800 x 800, centre 400,400). */
  radius: number;
  meaning: string;
}

/** Outside in. The crown has radius 0: it is the centre. */
export const RINGS: readonly Ring[] = [
  { id: 'perimeter', label: 'PERIMETER', radius: 316, meaning: 'Reached a decoy port' },
  { id: 'probe', label: 'PROBE', radius: 248, meaning: 'Guessing or probing for a way in' },
  { id: 'foothold', label: 'FOOTHOLD', radius: 180, meaning: 'Got past a login in the fiction' },
  { id: 'deep', label: 'DEEP', radius: 124, meaning: 'Working inside the fiction' },
  { id: 'crown', label: 'CROWN', radius: 0, meaning: 'Reached the synthetic crown jewel' },
];

export const RING_DEPTH: Record<RingId, number> = {
  perimeter: 0,
  probe: 1,
  foothold: 2,
  deep: 3,
  crown: 4,
};

export type LureId =
  | 'ssh:gate'
  | 'ssh:guess'
  | 'ssh:shell'
  | 'ssh:commands'
  | 'ssh:notes'
  | 'web:gate'
  | 'web:hidden'
  | 'web:env'
  | 'web:portal'
  | 'web:search'
  | 'crown';

export interface Lure {
  id: LureId;
  sector: Sector;
  ring: RingId;
  /** Short name drawn on the wheel. Our own text, never attacker text. */
  label: string;
  /** Second line on the wheel. */
  sublabel: string;
  /** What this place is in the fiction, for the detail panel. */
  detail: string;
  /** Bearing in degrees, SVG convention: 0 = 3 o'clock, 90 = 6 o'clock. */
  angle: number;
  /** Honeytoken ids planted at this lure. */
  holds?: string[];
  /** A gate is passed by every event in its sector. */
  gate?: boolean;
  /** Draw the label under the node instead of beside it, to keep it inside the block arc. */
  labelBelow?: boolean;
  source: string;
}

/*
 * Hand-placed bearings. The demo path spirals inward on the left, jumps across
 * the top (where the credential chord arcs over the crown), then spirals inward
 * on the right. Deterministic: a layout that moves between rehearsals helps
 * nobody under a projector.
 */
export const LURES: readonly Lure[] = [
  {
    id: 'ssh:gate',
    sector: 'ssh',
    ring: 'perimeter',
    label: 'SSH :2222',
    sublabel: 'ssh-decoy-01',
    detail:
      'The Cowrie SSH decoy on port 2222. Every SSH event passes this gate, so it lights as soon as anything reaches the decoy.',
    angle: 180,
    gate: true,
    source: 'deployment/docker-compose.yml',
  },
  {
    id: 'ssh:guess',
    sector: 'ssh',
    ring: 'probe',
    label: 'Login prompt',
    sublabel: 'password guesses',
    detail: 'The SSH login prompt. Rejected logins land here.',
    angle: 200,
    source: 'deployment/cowrie/userdb.txt',
  },
  {
    id: 'ssh:shell',
    sector: 'ssh',
    ring: 'foothold',
    label: 'Emulated shell',
    sublabel: 'login accepted',
    detail:
      'An accepted SSH login into the emulated shell. No real account or host exists behind it.',
    angle: 172,
    source: 'deployment/cowrie/cowrie.cfg',
  },
  {
    id: 'ssh:commands',
    sector: 'ssh',
    ring: 'deep',
    label: 'Shell commands',
    sublabel: 'emulated, not executed',
    detail:
      'Commands submitted to the emulated shell. Nothing runs on a real host; the decoy returns canned output.',
    angle: 140,
    source: 'decoys/ssh/lab_command_registry.py',
  },
  {
    id: 'ssh:notes',
    sector: 'ssh',
    ring: 'deep',
    label: 'notes.txt',
    sublabel: 'holds tok_portal_01',
    detail:
      'A planted note in /home/dg_demo. It contains the web portal credential for svc_portal, a honeytoken that only exists in this file.',
    angle: 222,
    holds: ['tok_portal_01'],
    source: 'deployment/cowrie/honeyfs/home/dg_demo/notes.txt',
  },
  {
    id: 'web:gate',
    sector: 'web',
    ring: 'perimeter',
    label: 'Web :8080',
    sublabel: 'web-decoy-01',
    detail:
      'The Flask web decoy on port 8080. Every web request passes this gate. A block closes it.',
    angle: 0,
    gate: true,
    source: 'decoys/web/app.py',
  },
  {
    id: 'web:hidden',
    sector: 'web',
    ring: 'probe',
    label: 'Hidden paths',
    sublabel: '/admin, /.git, …',
    detail:
      'Paths no real visitor would request, listed as hidden_paths. Requests here are probing, not browsing.',
    angle: 26,
    labelBelow: true,
    source: 'config/web_patterns.yaml',
  },
  {
    id: 'web:env',
    sector: 'web',
    ring: 'probe',
    label: '/.env',
    sublabel: 'holds tok_backup_01',
    detail:
      'A fake environment file. It contains an SSH credential for the backup user, a honeytoken that is only valid on the SSH decoy.',
    angle: -38,
    labelBelow: true,
    holds: ['tok_backup_01'],
    source: 'decoys/web/app.py',
  },
  {
    id: 'web:portal',
    sector: 'web',
    ring: 'foothold',
    label: 'Portal /login',
    sublabel: 'staff login',
    detail:
      'The staff portal login. The credential planted in notes.txt on the SSH decoy is accepted here.',
    angle: -22,
    source: 'decoys/web/app.py',
  },
  {
    id: 'web:search',
    sector: 'web',
    ring: 'deep',
    label: 'Search',
    sublabel: '/search',
    detail:
      'The portal search box. It answers injection attempts with a canned SQL error as bait. No query reaches a database.',
    angle: 28,
    source: 'decoys/web/app.py',
  },
  {
    id: 'crown',
    sector: 'core',
    ring: 'crown',
    label: 'customer_data.csv',
    sublabel: 'synthetic',
    detail:
      'The crown jewel: a synthetic customer export behind /download. Every row is fake (example.com addresses, DGLAB- secrets). Reaching it means the trail was followed all the way in.',
    angle: 0,
    source: 'decoys/web/assets/customer_data.csv',
  },
];

export const LURE_BY_ID: ReadonlyMap<LureId, Lure> = new Map(LURES.map((lure) => [lure.id, lure]));

export interface Token {
  id: string;
  plantedAt: LureId;
  /** Where presenting it means the trail was followed. */
  presentedAt: LureId;
  description: string;
}

/** Mirror of config/honeytokens.yaml. Ids and placement only, never values. */
export const TOKENS: readonly Token[] = [
  {
    id: 'tok_portal_01',
    plantedAt: 'ssh:notes',
    presentedAt: 'web:portal',
    description: 'Web portal login for svc_portal',
  },
  {
    id: 'tok_backup_01',
    plantedAt: 'web:env',
    presentedAt: 'ssh:shell',
    description: 'SSH login for the backup user',
  },
];

export const TOKEN_BY_ID: ReadonlyMap<string, Token> = new Map(TOKENS.map((t) => [t.id, t]));

/** config/web_patterns.yaml hidden_paths, minus /.env which is its own lure. */
const HIDDEN_PATHS = new Set([
  '/admin',
  '/administrator',
  '/.git/head',
  '/.git/config',
  '/backup.zip',
  '/backup',
  '/phpmyadmin',
  '/wp-admin',
  '/wp-login.php',
  '/server-status',
  '/config.php',
  '/db.sql',
  '/api/debug',
]);

function normalisePath(path: unknown): string {
  if (typeof path !== 'string') return '';
  const bare = path.split('?')[0] ?? '';
  return bare.toLowerCase().replace(/\/+$/, '') || '/';
}

/**
 * Which place in the fiction did this event reach? First match wins, deepest
 * first. Returns null for blocked requests: those bounced off the gate and
 * reached nothing, so the wheel draws them outside the perimeter instead.
 */
export function classify(event: SocEvent): LureId | null {
  if (event.event_type === 'blocked_request') return null;
  // The wheel maps the SSH and web fiction only. MySQL and SMB events (v1.2)
  // are never placed on a web lure; ChakraView says how many it leaves out.
  if (event.sensor_id !== 'ssh-decoy-01' && event.sensor_id !== 'web-decoy-01') return null;
  const attrs = event.attributes ?? {};

  if (event.sensor_id === 'ssh-decoy-01') {
    if (event.event_type === 'command_input') {
      const command = typeof attrs.command === 'string' ? attrs.command : '';
      return /notes\.txt/i.test(command) ? 'ssh:notes' : 'ssh:commands';
    }
    if (event.event_type === 'auth_success') return 'ssh:shell';
    if (event.event_type === 'auth_failure') return 'ssh:guess';
    return 'ssh:gate';
  }

  // web-decoy-01
  if (event.event_type === 'synthetic_file_access') return 'crown';
  const path = normalisePath(attrs.path);
  if (path === '/download') return 'crown';
  if (path === '/search') return 'web:search';
  if (path === '/login' || event.event_type === 'auth_success' || event.event_type === 'auth_failure') {
    return 'web:portal';
  }
  if (path === '/.env') return 'web:env';
  if (HIDDEN_PATHS.has(path)) return 'web:hidden';
  return 'web:gate';
}

export function gateOf(sector: Sector): LureId | null {
  if (sector === 'ssh') return 'ssh:gate';
  if (sector === 'web') return 'web:gate';
  return null;
}

export function sectorOfSensor(sensorId: string): Sector {
  return sensorId === 'ssh-decoy-01' ? 'ssh' : 'web';
}
