/**
 * Source profiles and session cases (review section 4).
 *
 * A source profile groups observations about one endpoint in one run; it is
 * never a person. A session case is one decoy session and stays distinct,
 * even when several share an address. Scores appear only where the backend
 * gave one for that object.
 */

import { Link as RouterLink } from 'react-router-dom';
import { CASE_COPY, SENSOR_LABEL } from '../../copy';
import { OUTCOMES, type SessionCase, type SourceProfile } from '../../evidence/model';
import { number, timeUtcZ } from '../../lib/format';
import { AttackerText } from '../primitives';
import { AuthorityTag, BasisTag, EvidenceIds, ModeBadge, OutcomeBadge } from './bits';

export interface EvidenceHandlers {
  onOpenEvent?: (eventId: string) => void;
  isKnown?: (eventId: string) => boolean;
}

function ScoreChip({ score, severity }: { score: number | null; severity: string | null }) {
  if (score === null || severity === null) {
    return (
      <span className="casescore casescore--none" title={CASE_COPY.unscoredV1}>
        not scored per case
      </span>
    );
  }
  return (
    <span className={`casescore badge badge--${severity}`}>
      {number(score)} {severity}
    </span>
  );
}

export function SourceProfileCard({ profile, ...handlers }: { profile: SourceProfile } & EvidenceHandlers) {
  return (
    <section className="evcard evcard--source" aria-label={`Source profile ${profile.src_ip}`}>
      <header className="evcard__head">
        <span className="evcard__kind">Source profile</span>
        <span className="mono evcard__title">{profile.src_ip}</span>
        <span className="evcard__sub mono">{profile.lab_run_id}</span>
        {profile.capture_modes.map((mode) => (
          <ModeBadge key={mode} mode={mode} />
        ))}
        <span className="evcard__spacer" />
        <BasisTag basis={profile.basis} />
      </header>
      <p className="evcard__note">{CASE_COPY.sourceIsEndpoint}</p>

      <dl className="evfacts">
        <div>
          <dt>Seen</dt>
          <dd className="mono">
            {timeUtcZ(profile.first_at)} → {timeUtcZ(profile.last_at)}
          </dd>
        </div>
        <div>
          <dt>Sensors</dt>
          <dd>
            {profile.sensors.map((sensor) => (
              <span key={sensor.sensor_id} className="evfacts__item">
                {SENSOR_LABEL[sensor.sensor_id] ?? sensor.sensor_id}: {sensor.cases} case
                {sensor.cases === 1 ? '' : 's'}, {sensor.events} event{sensor.events === 1 ? '' : 's'}
              </span>
            ))}
          </dd>
        </div>
        <div>
          <dt>Accounts tried</dt>
          <dd>
            {profile.attempted_accounts.length === 0 ? (
              <span className="state__hint">none</span>
            ) : (
              profile.attempted_accounts.map((account) => (
                <span key={account} className="evfacts__item">
                  <AttackerText value={account} />
                </span>
              ))
            )}
          </dd>
        </div>
        <div>
          <dt title={CASE_COPY.claims}>Client claims</dt>
          <dd>
            {profile.client_claims.length === 0 ? (
              <span className="state__hint">none</span>
            ) : (
              profile.client_claims.map((claim) => (
                <span key={`${claim.kind}-${claim.event_id}`} className="evfacts__claim">
                  <span className="evfacts__claimkind">
                    {claim.kind === 'ssh_client_version' ? 'SSH client' : 'User-Agent'}
                  </span>
                  <AttackerText value={claim.value} />
                  <EvidenceIds ids={[claim.event_id]} {...handlers} />
                </span>
              ))
            )}
          </dd>
        </div>
      </dl>

      {profile.source_score ? (
        <div className="evcard__sourcescore" title={CASE_COPY.sourceScoreV1}>
          <span className={`badge badge--${profile.source_score.severity}`}>
            {number(profile.source_score.score)} {profile.source_score.severity}
          </span>
          <span>{CASE_COPY.sourceScoreV1}</span>
        </div>
      ) : null}
    </section>
  );
}

export function SessionCaseCard({
  item,
  transcriptHref,
  ...handlers
}: { item: SessionCase; transcriptHref?: string | null } & EvidenceHandlers) {
  const outcomes = OUTCOMES.filter((outcome) => (item.outcomes[outcome] ?? 0) > 0);
  return (
    <article
      className={`casecard casecard--${item.boundary}`}
      aria-label={`Session case ${item.session_id ?? item.case_id}`}
      data-case-id={item.case_id}
    >
      <header className="casecard__head">
        <span className="casecard__sensor">{SENSOR_LABEL[item.sensor_id] ?? item.sensor_id}</span>
        <span className="mono casecard__session">
          {item.session_id ?? 'no session id'}
        </span>
        <ModeBadge mode={item.capture_mode} />
        <AuthorityTag authority={item.authority} />
        <span className="casecard__spacer" />
        <ScoreChip score={item.score} severity={item.severity} />
      </header>
      <p className="casecard__boundary">
        {item.boundary === 'sensor_session' ? CASE_COPY.sensorSession : CASE_COPY.boundedFallback}
      </p>
      <div className="casecard__row">
        <span className="mono casecard__time">
          {timeUtcZ(item.first_at)}
          {item.last_at !== item.first_at ? ` → ${timeUtcZ(item.last_at)}` : ''}
        </span>
        <span>
          {item.event_ids.length} event{item.event_ids.length === 1 ? '' : 's'}
        </span>
        {item.commands > 0 ? <span>{item.commands} cmd{item.commands === 1 ? '' : 's'}</span> : null}
        {item.accounts.length > 0 ? (
          <span className="casecard__accounts">
            as{' '}
            {item.accounts.map((account, index) => (
              <span key={account}>
                {index > 0 ? ', ' : ''}
                <AttackerText value={account} />
              </span>
            ))}
          </span>
        ) : null}
      </div>
      {outcomes.length > 0 || item.rule_ids.length > 0 ? (
        <div className="casecard__row">
          {outcomes.map((outcome) => (
            <OutcomeBadge key={outcome} outcome={outcome} count={item.outcomes[outcome]} />
          ))}
          {item.rule_ids.map((rule) => (
            <span key={rule} className="rulechip mono">
              {rule}
            </span>
          ))}
        </div>
      ) : null}
      {item.request_ids.length > 0 ? (
        <div className="casecard__row casecard__requests">
          <span className="casecard__label">requests</span>
          {item.request_ids.map((id) => (
            <span key={id} className="mono facet">
              {id}
            </span>
          ))}
        </div>
      ) : null}
      <footer className="casecard__foot">
        <EvidenceIds ids={item.event_ids} {...handlers} max={4} />
        <span className="casecard__links">
          {item.session_id ? (
            <RouterLink
              className="linkbtn"
              to={`/events?session=${encodeURIComponent(item.session_id)}&run=${encodeURIComponent(item.lab_run_id)}`}
            >
              Feed
            </RouterLink>
          ) : null}
          {transcriptHref ? (
            <RouterLink className="linkbtn" to={transcriptHref}>
              Transcript
            </RouterLink>
          ) : null}
        </span>
      </footer>
    </article>
  );
}
