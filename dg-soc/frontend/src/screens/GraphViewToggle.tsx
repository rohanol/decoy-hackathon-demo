/**
 * Switch between ChakraView and the original network graph on /graph.
 *
 * Both read the same API and the same link decisions. The network view stays
 * one click away as a fallback: if the wheel misbehaves under a projector, the
 * demo carries on without leaving the screen.
 */

import { useSearchParams } from 'react-router-dom';

export type GraphView = 'chakra' | 'network';

export function useGraphView(): GraphView {
  const [searchParams] = useSearchParams();
  return searchParams.get('view') === 'network' ? 'network' : 'chakra';
}

export function GraphViewToggle({ current }: { current: GraphView }) {
  const [searchParams, setSearchParams] = useSearchParams();

  const choose = (view: GraphView) => {
    const next = new URLSearchParams(searchParams);
    if (view === 'network') next.set('view', 'network');
    else next.delete('view');
    setSearchParams(next, { replace: true });
  };

  return (
    <div className="segmented" role="group" aria-label="Graph view">
      <button
        type="button"
        className={current === 'chakra' ? 'segmented__btn segmented__btn--active' : 'segmented__btn'}
        aria-pressed={current === 'chakra'}
        onClick={() => choose('chakra')}
      >
        Chakra
      </button>
      <button
        type="button"
        className={current === 'network' ? 'segmented__btn segmented__btn--active' : 'segmented__btn'}
        aria-pressed={current === 'network'}
        onClick={() => choose('network')}
      >
        Network
      </button>
    </div>
  );
}
