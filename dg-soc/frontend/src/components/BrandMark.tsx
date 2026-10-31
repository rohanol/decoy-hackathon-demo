import { Link } from 'react-router-dom';

/** Wordmark: a small node-and-edge glyph and the product name. */
export function BrandMark({ to = '/welcome', compact }: { to?: string; compact?: boolean }) {
  return (
    <Link to={to} className={compact ? 'brand brand--compact' : 'brand'}>
      <svg className="brand__glyph" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="6" cy="17" r="2.6" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <circle cx="18" cy="17" r="2.6" fill="none" stroke="currentColor" strokeWidth="1.8" />
        <circle cx="12" cy="6" r="3" fill="var(--neon)" />
        <path d="M8 15.4 10.6 8.6M16 15.4 13.4 8.6M8.6 17h6.8" stroke="currentColor" strokeWidth="1.8" />
      </svg>
      <span className="brand__name">
        DeceptionGraph{compact ? null : <span className="brand__tag">SOC</span>}
      </span>
    </Link>
  );
}
