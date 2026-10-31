/**
 * Small evidence primitives shared by every evidence view.
 *
 * Colour never carries meaning alone: every badge has text, and the text comes
 * from copy.ts. Green stays reserved for "live", per the theme.
 */

import {
  AUTHORITY_LABEL,
  AUTHORITY_MEANING,
  BASIS_LABEL,
  BASIS_MEANING,
  OBSERVATION_KIND_LABEL,
  OUTCOME_LABEL,
  OUTCOME_MEANING,
} from '../../copy';
import { facetOf, type Authority, type Basis, type Outcome } from '../../evidence/model';
import type { CaptureMode, SocEvent } from '../../types/api';

/** Where a panel's values came from. Shown on every evidence panel. */
export function BasisTag({ basis }: { basis: Basis }) {
  return (
    <span className={`basistag basistag--${basis}`} title={BASIS_MEANING[basis]}>
      {BASIS_LABEL[basis]}
    </span>
  );
}

/** Who owns a grouping: the backend, or this browser for display only. */
export function AuthorityTag({ authority }: { authority: Authority }) {
  return (
    <span className={`authtag authtag--${authority}`} title={AUTHORITY_MEANING[authority]}>
      {AUTHORITY_LABEL[authority]}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: CaptureMode | 'mixed' }) {
  const text = mode === 'live' ? 'LIVE' : mode === 'replay' ? 'REPLAY' : 'MIXED';
  const title =
    mode === 'live'
      ? 'Live sensor traffic'
      : mode === 'replay'
        ? 'Replayed capture: never drives live response'
        : 'Live and replayed observations together: flagged, never trusted for response';
  return (
    <span className={`modebadge modebadge--${mode}`} title={title}>
      {text}
    </span>
  );
}

const OUTCOME_TONE: Record<Outcome, string> = {
  attempted: 'neutral',
  emulated_success: 'danger',
  denied: 'muted',
  failed: 'muted',
  unknown: 'warn',
};

export function OutcomeBadge({ outcome, count }: { outcome: Outcome; count?: number }) {
  return (
    <span className={`outcome outcome--${OUTCOME_TONE[outcome]}`} title={OUTCOME_MEANING[outcome]}>
      {OUTCOME_LABEL[outcome]}
      {count !== undefined ? <span className="outcome__n">{count}</span> : null}
    </span>
  );
}

/**
 * The result facet of one event: the proposed outcome and observation kind
 * when present, otherwise the v1.0 fields that already say something,
 * labelled as v1.0. Never inferred from the event type.
 */
export function EventFacets({ event }: { event: SocEvent }) {
  const facet = facetOf(event);
  const parts = [];
  if (facet.outcome) parts.push(<OutcomeBadge key="o" outcome={facet.outcome} />);
  if (facet.observation_kind) {
    parts.push(
      <span key="k" className="facet">
        {OBSERVATION_KIND_LABEL[facet.observation_kind]}
      </span>,
    );
  }
  if (!facet.outcome && facet.v1_outcome) {
    parts.push(
      <span key="v" className="facet facet--v1" title="contract v1.0 attributes.outcome">
        v1.0 {facet.v1_outcome}
      </span>,
    );
  }
  if (!facet.outcome && facet.v1_response_class && facet.v1_response_class !== 'normal') {
    parts.push(
      <span key="r" className="facet facet--v1" title="contract v1.0 attributes.response_class">
        v1.0 {facet.v1_response_class.replace('_', ' ')}
      </span>,
    );
  }
  if (facet.request_id) {
    parts.push(
      <span key="q" className="facet mono" title="request_id">
        {facet.request_id}
      </span>,
    );
  }
  if (parts.length === 0) return null;
  return <span className="facets">{parts}</span>;
}

/** An event id that opens the raw event when it is loaded. */
export function EvidenceId({
  eventId,
  onOpen,
  known = true,
}: {
  eventId: string;
  onOpen?: (eventId: string) => void;
  known?: boolean;
}) {
  if (!onOpen || !known) {
    return (
      <span className="evid evid--static mono" title={known ? undefined : 'Not in the loaded window'}>
        {eventId}
      </span>
    );
  }
  return (
    <button type="button" className="evid mono" onClick={() => onOpen(eventId)} title="Open the raw event">
      {eventId}
    </button>
  );
}

export function EvidenceIds({
  ids,
  onOpen,
  isKnown,
  max = 6,
}: {
  ids: string[];
  onOpen?: (eventId: string) => void;
  isKnown?: (eventId: string) => boolean;
  max?: number;
}) {
  const shown = ids.slice(0, max);
  return (
    <span className="evids">
      {shown.map((id) => (
        <EvidenceId key={id} eventId={id} onOpen={onOpen} known={isKnown ? isKnown(id) : true} />
      ))}
      {ids.length > shown.length ? <span className="evids__more">+{ids.length - shown.length}</span> : null}
    </span>
  );
}
