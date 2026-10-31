/**
 * ChakraView in 3D. The same wheel model as the 2D view (chakra/model.ts), with
 * depth made literal: each ring sits lower than the one outside it, so the
 * planted fiction is a funnel and the crown jewel is at the bottom.
 *
 * Nothing here decides anything. A lure lights because the model placed real
 * events on it; it turns red because a backend finding cites it; a chord is a
 * link the backend reported. The scene only chooses where to draw them.
 *
 * Time is the fourth axis: ChakraView passes in a model built from the events
 * up to the timeline cursor, and this scene animates whatever changes, so
 * scrubbing replays how the source walked in.
 */

import { Html, Line, OrbitControls } from '@react-three/drei';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing';
import { useEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';
import type { Line2, OrbitControls as OrbitControlsImpl } from 'three-stdlib';
import type { ChordView, LureView, WheelModel } from './model';
import { LURES, RINGS, RING_DEPTH, type Lure, type LureId, type RingId } from './manifest';

export type ChakraSelection =
  | { kind: 'lure'; id: LureId }
  | { kind: 'chord'; linkId: string }
  | null;

export type CameraView = 'orbit' | 'top' | 'side';

/* ---------- geometry ---------- */

const PERIMETER = RINGS[0]?.radius ?? 316;
const SCALE = 5.2 / PERIMETER;
const DROP = 1.2;
const CROWN_Y = -5.1;

function ringY(ring: RingId): number {
  return ring === 'crown' ? CROWN_Y : -RING_DEPTH[ring] * DROP;
}

function lurePosition(lure: Lure): THREE.Vector3 {
  if (lure.ring === 'crown') return new THREE.Vector3(0, CROWN_Y, 0);
  const ring = RINGS.find((item) => item.id === lure.ring);
  const radius = (ring?.radius ?? PERIMETER) * SCALE;
  const angle = THREE.MathUtils.degToRad(lure.angle);
  // Manifest bearings use the SVG convention: 0 = 3 o'clock, 90 = 6 o'clock.
  return new THREE.Vector3(radius * Math.cos(angle), ringY(lure.ring), radius * Math.sin(angle));
}

const POSITIONS = new Map<LureId, THREE.Vector3>(LURES.map((lure) => [lure.id, lurePosition(lure)]));

function positionOf(id: LureId): THREE.Vector3 {
  return POSITIONS.get(id) ?? new THREE.Vector3();
}

function circlePoints(radius: number, y: number, segments = 160): THREE.Vector3[] {
  return Array.from({ length: segments + 1 }, (_, index) => {
    const angle = (index / segments) * Math.PI * 2;
    return new THREE.Vector3(radius * Math.cos(angle), y, radius * Math.sin(angle));
  });
}

/** Hand-placed label sides where two lures sit close in some camera view. */
const LABEL_SIDE: Partial<Record<LureId, 'left' | 'right' | 'above' | 'below'>> = {
  'ssh:gate': 'above',
  'web:gate': 'above',
  'ssh:notes': 'above',
  'web:env': 'above',
};

/* ---------- palette (matches tokens.css) ---------- */

const COLOR = {
  ring: '#2c2c2c',
  ringReached: '#9a9a96',
  untouched: '#3b3b3b',
  touched: new THREE.Color('#f4f4f2').multiplyScalar(1.6),
  flagged: new THREE.Color('#ff2d6a').multiplyScalar(2.2),
  pending: '#b69cff',
  confirmed: new THREE.Color('#ffffff').multiplyScalar(1.8),
  rejected: '#444444',
  trail: new THREE.Color('#f4f4f2').multiplyScalar(1.35),
  comet: new THREE.Color('#39ff88').multiplyScalar(2.6),
  block: '#4c9eff',
};

/* ---------- camera ---------- */

const VIEWS: Record<CameraView, { position: [number, number, number]; target: [number, number, number] }> = {
  orbit: { position: [0.6, 8.6, 15.2], target: [0, -1.5, 0] },
  top: { position: [0, 20, 0.01], target: [0, -2.2, 0] },
  side: { position: [0, -1.2, 17.5], target: [0, -2.4, 0] },
};

/** Glides the camera to a preset or to the selected lure; hands control back on drag. */
function CameraRig({ view, focus }: { view: CameraView; focus: THREE.Vector3 | null }) {
  const camera = useThree((state) => state.camera);
  const controls = useThree((state) => state.controls) as OrbitControlsImpl | null;
  const gliding = useRef(true);

  useEffect(() => {
    gliding.current = true;
  }, [view, focus]);

  useEffect(() => {
    if (!controls) return;
    const stop = () => {
      gliding.current = false;
    };
    controls.addEventListener('start', stop);
    return () => controls.removeEventListener('start', stop);
  }, [controls]);

  useFrame((_, delta) => {
    if (!gliding.current || !controls) return;
    const preset = VIEWS[view];
    const target = focus ? focus.clone() : new THREE.Vector3(...preset.target);
    const position = focus
      ? focus
          .clone()
          .add(camera.position.clone().sub(controls.target).normalize().multiplyScalar(9.5))
      : new THREE.Vector3(...preset.position);
    const k = 1 - Math.exp(-delta * 3.2);
    camera.position.lerp(position, k);
    controls.target.lerp(target, k);
    controls.update();
    if (camera.position.distanceTo(position) < 0.02 && controls.target.distanceTo(target) < 0.02) {
      gliding.current = false;
    }
  });

  return null;
}

/* ---------- the funnel ---------- */

function Funnel({ depth }: { depth: RingId | null }) {
  const reachedDepth = depth === null ? -1 : RING_DEPTH[depth];
  const rings = RINGS.filter((ring) => ring.id !== 'crown');

  // Faint walls between consecutive rings give the funnel its depth.
  const walls = useMemo(() => {
    const levels = [
      ...rings.map((ring) => ({ radius: ring.radius * SCALE, y: ringY(ring.id) })),
      { radius: 0.6, y: CROWN_Y },
    ];
    return levels.slice(0, -1).map((top, index) => {
      const bottom = levels[index + 1] ?? top;
      return { top, bottom };
    });
  }, [rings]);

  const floor = useMemo(() => {
    const grid = new THREE.PolarGridHelper(8, 16, 6, 96, '#1a1a1a', '#121212');
    grid.position.y = CROWN_Y - 0.6;
    return grid;
  }, []);

  return (
    <group>
      {rings.map((ring) => {
        const reached = RING_DEPTH[ring.id] <= reachedDepth;
        const radius = ring.radius * SCALE;
        const y = ringY(ring.id);
        return (
          <group key={ring.id}>
            <Line
              points={circlePoints(radius, y)}
              color={reached ? COLOR.ringReached : COLOR.ring}
              lineWidth={reached ? 1.6 : 1}
              transparent
              opacity={reached ? 0.9 : 0.7}
            />
            <Html position={[0, y + 0.08, -radius]} center zIndexRange={[10, 0]}>
              <div className={reached ? 'c3ring c3ring--reached' : 'c3ring'} title={ring.meaning}>
                {ring.label}
              </div>
            </Html>
          </group>
        );
      })}

      {walls.map(({ top, bottom }, index) => (
        <mesh key={index} position={[0, (top.y + bottom.y) / 2, 0]}>
          <cylinderGeometry args={[top.radius, bottom.radius, top.y - bottom.y, 96, 1, true]} />
          <meshBasicMaterial
            color="#ffffff"
            transparent
            opacity={0.022 + index * 0.006}
            side={THREE.DoubleSide}
            depthWrite={false}
          />
        </mesh>
      ))}

      {/* The sector seam: SSH on the left, web on the right. */}
      {[90, 270].map((bearing) => (
        <Line
          key={bearing}
          points={[...rings.map((ring) => {
            const angle = THREE.MathUtils.degToRad(bearing);
            const radius = ring.radius * SCALE;
            return new THREE.Vector3(radius * Math.cos(angle), ringY(ring.id), radius * Math.sin(angle));
          }), new THREE.Vector3(0, CROWN_Y, 0)]}
          color="#2a2a2a"
          lineWidth={1}
          dashed
          dashSize={0.12}
          gapSize={0.1}
        />
      ))}

      <Html position={[-PERIMETER * SCALE * 0.7, 1.5, -PERIMETER * SCALE * 0.7]} center zIndexRange={[10, 0]}>
        <div className="c3sector">SSH decoy</div>
      </Html>
      <Html position={[PERIMETER * SCALE * 0.7, 1.5, -PERIMETER * SCALE * 0.7]} center zIndexRange={[10, 0]}>
        <div className="c3sector">Web decoy</div>
      </Html>

      <primitive object={floor} />
    </group>
  );
}

/* ---------- lures ---------- */

function Shockwave({ trigger, color }: { trigger: number; color: THREE.ColorRepresentation }) {
  const mesh = useRef<THREE.Mesh>(null);
  const started = useRef<number | null>(null);

  useEffect(() => {
    if (trigger > 0) started.current = performance.now();
  }, [trigger]);

  useFrame(() => {
    const ring = mesh.current;
    if (!ring) return;
    if (started.current === null) {
      ring.visible = false;
      return;
    }
    const t = (performance.now() - started.current) / 1300;
    if (t >= 1) {
      started.current = null;
      ring.visible = false;
      return;
    }
    ring.visible = true;
    const scale = 1 + t * 5;
    ring.scale.set(scale, scale, scale);
    (ring.material as THREE.MeshBasicMaterial).opacity = (1 - t) * 0.9;
  });

  return (
    <mesh ref={mesh} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
      <ringGeometry args={[0.2, 0.24, 48]} />
      <meshBasicMaterial color={color} transparent depthWrite={false} toneMapped={false} />
    </mesh>
  );
}

function LureNode({
  view,
  selected,
  awaiting,
  animate,
  onSelect,
}: {
  view: LureView;
  selected: boolean;
  awaiting: boolean;
  animate: boolean;
  onSelect: () => void;
}) {
  const { lure, state } = view;
  const position = positionOf(lure.id);
  const isCrown = lure.id === 'crown';
  const body = useRef<THREE.Group>(null);
  const pulse = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);

  // Ignite on the transition into "reached", never on first draw: replaying
  // history as fireworks on page load would be decoration.
  const previous = useRef(state);
  const [ignite, setIgnite] = useState(0);
  useEffect(() => {
    if (previous.current === 'untouched' && state !== 'untouched' && animate) {
      setIgnite((count) => count + 1);
    }
    previous.current = state;
  }, [state, animate]);

  const popAt = useRef<number | null>(null);
  useEffect(() => {
    if (ignite > 0) popAt.current = performance.now();
  }, [ignite]);

  useFrame((frame, delta) => {
    const group = body.current;
    if (!group) return;
    let scale = hovered || selected ? 1.25 : 1;
    if (popAt.current !== null) {
      const t = (performance.now() - popAt.current) / 600;
      if (t >= 1) popAt.current = null;
      else scale += Math.sin(t * Math.PI) * 0.8;
    }
    const k = 1 - Math.exp(-delta * 10);
    group.scale.setScalar(THREE.MathUtils.lerp(group.scale.x, scale, k));
    if (isCrown) group.rotation.y += delta * 0.35;
    if (pulse.current) {
      const t = (frame.clock.elapsedTime % 1.6) / 1.6;
      pulse.current.scale.setScalar(1 + t * 0.9);
      (pulse.current.material as THREE.MeshBasicMaterial).opacity = (1 - t) * 0.8;
    }
  });

  const color =
    state === 'flagged' ? COLOR.flagged : state === 'touched' ? COLOR.touched : COLOR.untouched;
  const lit = state !== 'untouched';
  const side = isCrown
    ? 'below'
    : (LABEL_SIDE[lure.id] ?? (position.x >= 0 ? 'right' : 'left'));
  // The second line is detail: shown when it carries a finding, or on demand.
  const showSub = state === 'flagged' || hovered || selected;
  const radius = isCrown ? 0.36 : lure.gate ? 0.17 : 0.14;

  return (
    <group position={position}>
      <group
        ref={body}
        onClick={(event) => {
          event.stopPropagation();
          onSelect();
        }}
        onPointerOver={(event) => {
          event.stopPropagation();
          setHovered(true);
          document.body.style.cursor = 'pointer';
        }}
        onPointerOut={() => {
          setHovered(false);
          document.body.style.cursor = '';
        }}
      >
        {isCrown ? (
          <>
            <mesh>
              <icosahedronGeometry args={[radius, 0]} />
              <meshStandardMaterial
                color={lit ? color : '#202020'}
                emissive={lit ? color : '#000000'}
                emissiveIntensity={lit ? 0.9 : 0}
                flatShading
                toneMapped={!lit}
              />
            </mesh>
            <mesh>
              <icosahedronGeometry args={[radius * 1.45, 1]} />
              <meshBasicMaterial color={lit ? color : '#3a3a3a'} wireframe transparent opacity={0.35} toneMapped={false} />
            </mesh>
          </>
        ) : (
          <mesh>
            <sphereGeometry args={[radius, 32, 32]} />
            {lit ? (
              <meshBasicMaterial color={color} toneMapped={false} />
            ) : (
              <meshStandardMaterial color={COLOR.untouched} roughness={0.6} />
            )}
          </mesh>
        )}

        {/* Invisible, larger hit target so small lures are easy to click. */}
        <mesh>
          <sphereGeometry args={[radius * 2.4, 12, 12]} />
          <meshBasicMaterial transparent opacity={0} depthWrite={false} />
        </mesh>

        {lure.holds ? (
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <torusGeometry args={[radius + 0.13, 0.014, 8, 64]} />
            <meshBasicMaterial color={COLOR.pending} toneMapped={false} />
          </mesh>
        ) : null}

        {selected ? (
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <torusGeometry args={[radius + 0.24, 0.02, 8, 64]} />
            <meshBasicMaterial color="#ffffff" toneMapped={false} />
          </mesh>
        ) : null}
      </group>

      {awaiting ? (
        <mesh ref={pulse} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[radius + 0.16, radius + 0.2, 48]} />
          <meshBasicMaterial color={COLOR.pending} transparent depthWrite={false} toneMapped={false} />
        </mesh>
      ) : null}

      <Shockwave trigger={ignite} color={state === 'flagged' ? COLOR.flagged : COLOR.touched} />

      <Html position={[0, 0, 0]} zIndexRange={[20, 0]}>
        <div
          className={`c3label c3label--${side} c3label--${state}${selected ? ' c3label--selected' : ''}`}
          onClick={onSelect}
        >
          <span className="c3label__name">
            {view.order !== null ? <span className="c3label__n">{view.order}</span> : null}
            {lure.label}
          </span>
          {showSub ? (
            <span className="c3label__sub">
              {view.rules.length > 0 ? view.rules.join(' ') : lure.sublabel}
            </span>
          ) : null}
        </div>
      </Html>
    </group>
  );
}

/* ---------- the trail and the comet ---------- */

/**
 * The order the source first reached each lure, as one curve. When a lure is
 * added the line grows into it rather than appearing whole.
 */
function Trail({ trail, comet }: { trail: LureId[]; comet: boolean }) {
  const line = useRef<Line2>(null);
  const head = useRef<THREE.Mesh>(null);
  const drawn = useRef(0);

  const { points, curve, anchors } = useMemo(() => {
    const anchorPoints = trail.map((id) => positionOf(id));
    if (anchorPoints.length < 2) return { points: [] as THREE.Vector3[], curve: null, anchors: anchorPoints };
    const path = new THREE.CatmullRomCurve3(anchorPoints, false, 'centripetal', 0.5);
    return { points: path.getPoints(Math.max(60, trail.length * 28)), curve: path, anchors: anchorPoints };
  }, [trail]);

  useFrame((frame, delta) => {
    const segments = Math.max(0, points.length - 1);
    drawn.current = Math.min(segments, drawn.current + delta * 70);
    const geometry = line.current?.geometry as (THREE.InstancedBufferGeometry & { instanceCount: number }) | undefined;
    if (geometry) geometry.instanceCount = Math.floor(drawn.current);
    const dot = head.current;
    if (dot && curve) {
      const visible = segments > 0 ? drawn.current / segments : 0;
      const t = comet ? ((frame.clock.elapsedTime * 0.12) % 1) * visible : visible;
      dot.position.copy(curve.getPointAt(Math.min(1, Math.max(0, t))));
      dot.visible = visible > 0;
    }
  });

  if (anchors.length < 2 || !curve) return null;

  return (
    <group>
      <Line ref={line} points={points} color={COLOR.trail} lineWidth={2.4} toneMapped={false} />
      <mesh ref={head}>
        <sphereGeometry args={[0.075, 16, 16]} />
        <meshBasicMaterial color={COLOR.comet} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ---------- chords ---------- */

function Chord({
  chord,
  selected,
  onSelect,
}: {
  chord: ChordView;
  selected: boolean;
  onSelect: () => void;
}) {
  const line = useRef<Line2>(null);
  const status = chord.link.status;

  const { points, mid, curve } = useMemo(() => {
    const start = positionOf(chord.from);
    const end = positionOf(chord.to);
    const lift = Math.max(start.y, end.y) + 3.4;
    const control = start.clone().add(end).multiplyScalar(0.5).setY(lift);
    const bezier = new THREE.QuadraticBezierCurve3(start, control, end);
    return { points: bezier.getPoints(64), mid: bezier.getPoint(0.5), curve: bezier };
  }, [chord.from, chord.to]);

  const tube = useMemo(() => new THREE.TubeGeometry(curve, 48, 0.12, 6, false), [curve]);

  useFrame((_, delta) => {
    // An open link flows, to say "this is waiting on you"; a decided one is still.
    const material = line.current?.material as { dashOffset: number } | undefined;
    if (material && status === 'open') material.dashOffset -= delta * 0.8;
  });

  const color =
    status === 'confirmed' ? COLOR.confirmed : status === 'rejected' ? COLOR.rejected : COLOR.pending;

  return (
    <group>
      <Line
        ref={line}
        points={points}
        color={color}
        lineWidth={selected ? 3.2 : status === 'confirmed' ? 2.6 : 1.8}
        dashed={status !== 'confirmed'}
        dashSize={0.22}
        gapSize={0.14}
        transparent
        opacity={status === 'rejected' ? 0.5 : 1}
        toneMapped={false}
      />
      <mesh
        geometry={tube}
        onClick={(event) => {
          event.stopPropagation();
          onSelect();
        }}
        onPointerOver={() => {
          document.body.style.cursor = 'pointer';
        }}
        onPointerOut={() => {
          document.body.style.cursor = '';
        }}
      >
        <meshBasicMaterial transparent opacity={0} depthWrite={false} />
      </mesh>
      <Html position={mid} center zIndexRange={[30, 0]}>
        <button
          type="button"
          className={`c3chord c3chord--${status}${selected ? ' c3chord--selected' : ''}`}
          onClick={onSelect}
        >
          {chord.token ? chord.token.id : 'same source'}
          <span>
            {status === 'open' ? 'awaiting' : status === 'confirmed' ? 'confirmed' : 'rejected'}
          </span>
        </button>
      </Html>
    </group>
  );
}

/* ---------- the web gate and the block ---------- */

function GateBlock({ model }: { model: WheelModel }) {
  const action = model.gate.action;
  const bounced = model.gate.bounced;
  const radius = PERIMETER * SCALE + 0.45;
  const span = THREE.MathUtils.degToRad(80);

  const bouncePoints = useMemo(
    () =>
      bounced.slice(0, 40).map((_, index) => {
        const angle = THREE.MathUtils.degToRad(-30 + ((index * 37) % 60));
        const r = radius + 0.5 + ((index * 13) % 7) * 0.08;
        return new THREE.Vector3(r * Math.cos(angle), 0.1 + ((index * 7) % 5) * 0.12, r * Math.sin(angle));
      }),
    [bounced, radius],
  );

  if (!action && bounced.length === 0) return null;

  return (
    <group>
      {action ? (
        <>
          {/* Cylinder theta runs from +z toward +x; the web gate sits on +x. */}
          <mesh position={[0, 0.25, 0]}>
            <cylinderGeometry args={[radius, radius, 1.1, 48, 1, true, Math.PI / 2 - span / 2, span]} />
            <meshBasicMaterial
              color={COLOR.block}
              transparent
              opacity={0.16}
              side={THREE.DoubleSide}
              depthWrite={false}
            />
          </mesh>
          <Html position={[radius + 0.2, 1.05, 0]} center zIndexRange={[25, 0]}>
            <div className="c3block">Block {action.status}</div>
          </Html>
        </>
      ) : null}
      {bouncePoints.map((point, index) => (
        <mesh key={index} position={point}>
          <sphereGeometry args={[0.045, 8, 8]} />
          <meshBasicMaterial color={COLOR.block} toneMapped={false} />
        </mesh>
      ))}
    </group>
  );
}

/* ---------- ambience ---------- */

function Dust() {
  const points = useRef<THREE.Points>(null);
  const geometry = useMemo(() => {
    const positions = new Float32Array(500 * 3);
    for (let index = 0; index < 500; index += 1) {
      const r = 6 + Math.random() * 10;
      const theta = Math.random() * Math.PI * 2;
      positions[index * 3] = r * Math.cos(theta);
      positions[index * 3 + 1] = -8 + Math.random() * 14;
      positions[index * 3 + 2] = r * Math.sin(theta);
    }
    const buffer = new THREE.BufferGeometry();
    buffer.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    return buffer;
  }, []);

  useFrame((_, delta) => {
    if (points.current) points.current.rotation.y += delta * 0.01;
  });

  return (
    <points ref={points} geometry={geometry}>
      <pointsMaterial color="#5a5a5a" size={0.03} sizeAttenuation transparent opacity={0.6} />
    </points>
  );
}

/* ---------- scene ---------- */

export default function Chakra3D({
  model,
  selection,
  awaitingLures,
  view,
  autoRotate,
  animate,
  onSelect,
}: {
  model: WheelModel;
  selection: ChakraSelection;
  awaitingLures: Set<LureId>;
  view: CameraView;
  autoRotate: boolean;
  animate: boolean;
  onSelect: (selection: ChakraSelection) => void;
}) {
  const focus = useMemo(
    () => (selection?.kind === 'lure' ? positionOf(selection.id) : null),
    [selection],
  );

  return (
    <Canvas
      dpr={[1, 1.75]}
      camera={{ position: VIEWS.orbit.position, fov: 42, near: 0.1, far: 100 }}
      gl={{ antialias: true, powerPreference: 'high-performance' }}
      onPointerMissed={(event) => {
        // Labels are DOM over the canvas; a click on one is not a miss.
        const target = event.target as Element | null;
        if (target?.closest?.('.c3label, .c3chord')) return;
        onSelect(null);
      }}
    >
      <color attach="background" args={['#070707']} />
      <fog attach="fog" args={['#070707', 18, 34]} />
      <ambientLight intensity={0.5} />
      <directionalLight position={[4, 8, 6]} intensity={1.4} />
      <pointLight position={[0, CROWN_Y + 1.5, 0]} intensity={4} distance={6} color="#ff2d6a" />

      <Funnel depth={model.depth} />
      <Trail trail={model.trail} comet={animate} />

      {[...model.lures.values()].map((lureView) => (
        <LureNode
          key={lureView.lure.id}
          view={lureView}
          selected={selection?.kind === 'lure' && selection.id === lureView.lure.id}
          awaiting={awaitingLures.has(lureView.lure.id)}
          animate={animate}
          onSelect={() => onSelect({ kind: 'lure', id: lureView.lure.id })}
        />
      ))}

      {model.chords.map((chord) => (
        <Chord
          key={chord.link.link_id}
          chord={chord}
          selected={selection?.kind === 'chord' && selection.linkId === chord.link.link_id}
          onSelect={() => onSelect({ kind: 'chord', linkId: chord.link.link_id })}
        />
      ))}

      <GateBlock model={model} />
      {animate ? <Dust /> : null}

      <OrbitControls
        makeDefault
        enableDamping
        dampingFactor={0.08}
        autoRotate={autoRotate && selection === null}
        autoRotateSpeed={0.45}
        minDistance={4}
        maxDistance={26}
        maxPolarAngle={Math.PI * 0.62}
        enablePan={false}
      />
      <CameraRig view={view} focus={focus} />

      <EffectComposer multisampling={0}>
        <Bloom intensity={0.85} luminanceThreshold={0.62} luminanceSmoothing={0.2} mipmapBlur />
        <Vignette eskil={false} offset={0.2} darkness={0.75} />
      </EffectComposer>
    </Canvas>
  );
}
