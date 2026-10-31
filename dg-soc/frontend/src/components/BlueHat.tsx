import { lazy, Suspense, useMemo } from 'react';
import { ErrorBoundary, webglAvailable } from './ErrorBoundary';

const BlueHatScene = lazy(() => import('../three/BlueHatScene'));

/** Flat fallback when WebGL is missing, so the mark never disappears. */
function FlatHat() {
  return (
    <svg viewBox="0 0 64 40" className="bluehat__flat" aria-hidden="true">
      <path d="M18 24 C18 10 24 6 32 6 C40 6 46 10 46 24 Z" fill="#2563eb" />
      <rect x="18" y="20" width="28" height="5" fill="#0a1633" />
      <ellipse cx="32" cy="27" rx="28" ry="6" fill="#1d4fd8" />
    </svg>
  );
}

/** The blue team mark, as a small lazily loaded 3D hat. */
export function BlueHat({ spin, className }: { spin?: number; className?: string }) {
  const canRender = useMemo(() => webglAvailable(), []);
  return (
    <div className={className ? `bluehat ${className}` : 'bluehat'} aria-hidden="true">
      {canRender ? (
        <ErrorBoundary fallback={<FlatHat />}>
          <Suspense fallback={null}>
            <BlueHatScene spin={spin} />
          </Suspense>
        </ErrorBoundary>
      ) : (
        <FlatHat />
      )}
    </div>
  );
}
