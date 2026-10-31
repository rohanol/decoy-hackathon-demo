/**
 * The blue hat: the blue team's mark. Built from geometry in code, so there is
 * no model file to download and nothing to load over a network the lab does
 * not have. A fedora is two lathed profiles (crown and brim) and a band.
 */

import { Canvas, useFrame } from '@react-three/fiber';
import { useMemo, useRef } from 'react';
import * as THREE from 'three';

function profile(points: [number, number][]) {
  return points.map(([x, y]) => new THREE.Vector2(x, y));
}

function Hat({ spin }: { spin: number }) {
  const group = useRef<THREE.Group>(null);

  const crown = useMemo(
    () =>
      new THREE.LatheGeometry(
        profile([
          [0.0, 0.42],
          [0.14, 0.47],
          [0.3, 0.6],
          [0.44, 0.68],
          [0.53, 0.65],
          [0.58, 0.48],
          [0.61, 0.22],
          [0.63, 0.02],
        ]),
        64,
      ),
    [],
  );
  const brim = useMemo(
    () =>
      new THREE.LatheGeometry(
        profile([
          [0.6, 0.03],
          [0.86, 0.02],
          [1.06, 0.06],
          [1.16, 0.13],
          [1.18, 0.1],
          [1.1, 0.02],
          [0.88, -0.03],
          [0.6, -0.02],
        ]),
        96,
      ),
    [],
  );

  useFrame((state, delta) => {
    const hat = group.current;
    if (!hat) return;
    hat.rotation.y += delta * spin;
    hat.position.y = Math.sin(state.clock.elapsedTime * 1.2) * 0.04;
  });

  return (
    <group ref={group} rotation={[0.38, 0, 0.06]}>
      <mesh geometry={crown}>
        <meshStandardMaterial
          color="#2563eb"
          roughness={0.55}
          metalness={0.05}
          side={THREE.DoubleSide}
        />
      </mesh>
      <mesh geometry={brim}>
        <meshStandardMaterial
          color="#1d4fd8"
          roughness={0.6}
          metalness={0.05}
          side={THREE.DoubleSide}
        />
      </mesh>
      <mesh position={[0, 0.1, 0]}>
        <cylinderGeometry args={[0.622, 0.632, 0.13, 64, 1, true]} />
        <meshStandardMaterial color="#0a1633" roughness={0.8} side={THREE.DoubleSide} />
      </mesh>
    </group>
  );
}

export default function BlueHatScene({ spin = 0.45 }: { spin?: number }) {
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: [0, 0.7, 4.1], fov: 32 }}
      gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
    >
      <ambientLight intensity={0.55} />
      <directionalLight position={[-2, 3, 2]} intensity={2.2} color="#ffffff" />
      {/* A green rim from behind ties the hat to the console's one accent. */}
      <directionalLight position={[2, 1, -3]} intensity={1.6} color="#39ff88" />
      <pointLight position={[0, -2, 2]} intensity={0.6} color="#5cb8ff" />
      <Hat spin={spin} />
    </Canvas>
  );
}
