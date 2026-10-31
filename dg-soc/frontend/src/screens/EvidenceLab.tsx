/**
 * Evidence lab — DEVELOPMENT ONLY.
 *
 * Renders every proposed-shape scenario in src/evidence/devScenarios.ts
 * through the same components the live screens use, so each display can be
 * checked against its review acceptance case before Rohan's contract lands.
 *
 * Routed only in a fixture build (VITE_USE_FIXTURES=1). A normal build has no
 * route, no nav item and no scenario data: the import is dead code there.
 */

import { useMemo, useState } from 'react';
import { RawEventDrawer } from '../components/RawEventDrawer';
import { SessionCaseCard, SourceProfileCard } from '../components/evidence/CaseViews';
import { HealthDimensions } from '../components/evidence/HealthDimensions';
import { MappingList } from '../components/evidence/MappingViews';
import { OrphanUseCard, ParentCard, RelationCard } from '../components/evidence/RelationViews';
import {
  EligibilityNotice,
  GatedActionButton,
  VerificationTimeline,
} from '../components/evidence/ResponseViews';
import { BasisTag, EventFacets, EvidenceId, ModeBadge } from '../components/evidence/bits';
import { AttackerText } from '../components/primitives';
import { eventTypeLabel } from '../copy';
import { buildDevScenarios, type DevScenario } from '../evidence/devScenarios';
import { timeUtcZ } from '../lib/format';
import type { SocEvent } from '../types/api';

function gist(event: SocEvent): string {
  const a = event.attributes ?? {};
  if (typeof a.command === 'string') return a.command;
  if (typeof a.path === 'string') return `${a.method ?? ''} ${a.path}${a.query_redacted ? `?${a.query_redacted}` : ''}`.trim();
  if (typeof a.asset_id === 'string') return a.asset_id;
  if (typeof a.username === 'string') return `username=${a.username}`;
  return '';
}

function Scenario({ scenario, onOpen }: { scenario: DevScenario; onOpen: (event: SocEvent) => void }) {
  const byId = useMemo(() => new Map(scenario.events.map((event) => [event.event_id, event])), [scenario.events]);
  const handlers = {
    onOpenEvent: (id: string) => {
      const event = byId.get(id);
      if (event) onOpen(event);
    },
    isKnown: (id: string) => byId.has(id),
  };
  const cases = scenario.cases ?? [];
  const [now] = useState(() => new Date());

  return (
    <section className="devlab__scenario" id={scenario.id} aria-label={scenario.title}>
      <header className="devlab__head">
        <h2 className="devlab__title">{scenario.title}</h2>
        {scenario.review.map((id) => (
          <span key={id} className="pill">
            {id}
          </span>
        ))}
        <span style={{ flex: 1 }} />
        <BasisTag basis="proposed_fixture" />
      </header>
      <p className="devlab__expect">
        <strong>Must show:</strong> {scenario.expect}
      </p>

      {scenario.profile ? <SourceProfileCard profile={scenario.profile} {...handlers} /> : null}

      {cases.length > 0 ? (
        <>
          <div className="evsection__label">Session cases</div>
          <div className="casegrid">
            {cases.map((item) => (
              <SessionCaseCard key={item.case_id} item={item} {...handlers} />
            ))}
          </div>
        </>
      ) : null}

      {scenario.parents?.map((parent) => (
        <ParentCard key={parent.parent_id} parent={parent} cases={cases} relations={scenario.relations ?? []} />
      ))}

      {scenario.relations && scenario.relations.length > 0 ? (
        <>
          <div className="evsection__label">Relations</div>
          <div className="rellist">
            {scenario.relations.map((relation) => (
              <RelationCard key={relation.relation_id} relation={relation} cases={cases} {...handlers} />
            ))}
          </div>
        </>
      ) : null}

      {scenario.orphans?.map((bait) => (
        <OrphanUseCard key={bait.presented.event_id} bait={bait} {...handlers} />
      ))}

      {scenario.mappings ? <MappingList mappings={scenario.mappings} basis="proposed_fixture" {...handlers} /> : null}

      {scenario.health ? <HealthDimensions view={scenario.health} stream="live" now={now} /> : null}

      {scenario.verifications ? (
        <div className="rellist">
          {scenario.verifications.map((verification) => (
            <VerificationTimeline key={verification.action_id} verification={verification} {...handlers} />
          ))}
        </div>
      ) : null}

      {scenario.eligibility ? (
        <div className="rellist">
          {scenario.eligibility.map(({ label, value }) => (
            <div key={label} className="relcard">
              <div className="relcard__head">
                <span className="relcard__phrase">{label}</span>
              </div>
              <EligibilityNotice eligibility={value} />
              <div>
                <GatedActionButton eligibility={value} onClick={() => undefined}>
                  Block source…
                </GatedActionButton>
              </div>
            </div>
          ))}
        </div>
      ) : null}

      {scenario.events.length > 0 ? (
        <details>
          <summary className="state__hint" style={{ textAlign: 'left', cursor: 'pointer' }}>
            {scenario.events.length} fixture events with their facets
          </summary>
          <table className="devlab__events">
            <tbody>
              {scenario.events.map((event) => (
                <tr key={event.event_id}>
                  <td>
                    <EvidenceId eventId={event.event_id} onOpen={handlers.onOpenEvent} />
                  </td>
                  <td className="mono">{timeUtcZ(event.occurred_at)}</td>
                  <td>{eventTypeLabel(event.event_type)}</td>
                  <td>
                    <ModeBadge mode={event.capture_mode} />
                  </td>
                  <td>
                    <AttackerText value={gist(event)} />
                  </td>
                  <td>
                    <EventFacets event={event} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      ) : null}
    </section>
  );
}

export function EvidenceLab() {
  const scenarios = useMemo(() => buildDevScenarios(), []);
  const [open, setOpen] = useState<SocEvent | null>(null);

  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">Evidence lab</h1>
        <span className="page__head-spacer" />
        <span className="pill pill--warn">DEV FIXTURES</span>
      </div>
      <div className="devlab__banner" role="note">
        Development fixtures in the <strong>proposed</strong> evidence shape, pending the agreed
        contract. Not captured data, and not on the demo path: this page exists only in a fixture
        build. Each scenario names the review acceptance case it exercises.
      </div>
      <nav className="devlab__nav" aria-label="Scenarios">
        {scenarios.map((scenario) => (
          <a key={scenario.id} className="pill" href={`#${scenario.id}`}>
            {scenario.title}
          </a>
        ))}
      </nav>
      {scenarios.map((scenario) => (
        <Scenario key={scenario.id} scenario={scenario} onOpen={setOpen} />
      ))}
      {open ? <RawEventDrawer event={open} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}
