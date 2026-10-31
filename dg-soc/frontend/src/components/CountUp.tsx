import { animate } from 'motion/react';
import { useEffect, useRef, useState } from 'react';

/**
 * A number that rolls to its new value. Display only: the value itself comes
 * from the API untouched, and the final frame always shows it exactly.
 */
export function CountUp({
  value,
  format,
  duration = 0.9,
}: {
  value: number;
  format: (value: number) => string;
  duration?: number;
}) {
  const [shown, setShown] = useState(value);
  const fromRef = useRef(0);

  useEffect(() => {
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    if (reduced) {
      setShown(value);
      fromRef.current = value;
      return;
    }
    const controls = animate(fromRef.current, value, {
      duration,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (latest) => setShown(latest),
      onComplete: () => setShown(value),
    });
    fromRef.current = value;
    return () => controls.stop();
  }, [value, duration]);

  return <>{format(shown === value ? value : shown)}</>;
}
