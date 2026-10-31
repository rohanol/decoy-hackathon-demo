import { AttackGraph } from './AttackGraph';
import { ChakraView } from './ChakraView';
import { useGraphView } from './GraphViewToggle';

/** /graph: ChakraView by default, the network graph with ?view=network. */
export function GraphRoute() {
  return useGraphView() === 'network' ? <AttackGraph /> : <ChakraView />;
}
