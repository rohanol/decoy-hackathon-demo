/**
 * Falling binary behind the landing and login pages. Decoration only, so it is
 * deliberately quiet: low alpha, ~20 fps, paused when the tab is hidden, and a
 * single still frame for people who ask for reduced motion.
 */

import { useEffect, useRef } from 'react';

const CELL = 18;
const FPS = 20;

export function BinaryRain({ strength = 1 }: { strength?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;

    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    let width = 0;
    let height = 0;
    let drops: { y: number; speed: number; active: boolean }[] = [];

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = "500 13px 'JetBrains Mono Variable', ui-monospace, monospace";
      ctx.textBaseline = 'top';
      const columns = Math.ceil(width / CELL);
      drops = Array.from({ length: columns }, () => ({
        y: Math.random() * (height / CELL),
        speed: 0.25 + Math.random() * 0.55,
        active: Math.random() < 0.55,
      }));
      ctx.fillStyle = '#050505';
      ctx.fillRect(0, 0, width, height);
    };

    const step = () => {
      // Fade what is already there, so each column leaves a short tail.
      ctx.fillStyle = 'rgba(5, 5, 5, 0.14)';
      ctx.fillRect(0, 0, width, height);
      drops.forEach((drop, column) => {
        if (!drop.active) {
          if (Math.random() < 0.004) drop.active = true;
          return;
        }
        const bit = Math.random() < 0.5 ? '0' : '1';
        const x = column * CELL + 3;
        const y = Math.floor(drop.y) * CELL;
        ctx.fillStyle = `rgba(57, 255, 136, ${0.42 * strength})`;
        ctx.fillText(bit, x, y);
        drop.y += drop.speed;
        if (y > height && Math.random() > 0.96) {
          drop.y = 0;
          drop.speed = 0.25 + Math.random() * 0.55;
          drop.active = Math.random() < 0.7;
        }
      });
    };

    resize();
    let timer: number | null = null;
    const start = () => {
      if (timer === null && !reduced) timer = window.setInterval(step, 1000 / FPS);
    };
    const stop = () => {
      if (timer !== null) window.clearInterval(timer);
      timer = null;
    };
    if (reduced) for (let i = 0; i < 60; i += 1) step();
    start();

    const onVisibility = () => (document.hidden ? stop() : start());
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      observer.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [strength]);

  return <canvas ref={canvasRef} className="binaryrain" aria-hidden="true" />;
}
