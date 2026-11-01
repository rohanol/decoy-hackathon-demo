/**
 * Mapping rationale (review section 5). A technique id only with a reason and
 * an observation status; "no technique" is a valid, explicit answer.
 */

import { MAPPING_COPY, RULE_NAME } from '../../copy';
import type { Basis, MappingView } from '../../evidence/model';
import { BasisTag, EvidenceIds } from './bits';
import type { EvidenceHandlers } from './CaseViews';

export function MappingRationale({ mapping, ...handlers }: { mapping: MappingView } & EvidenceHandlers) {
  return (
    <div className="mapping" data-rule={mapping.rule_id}>
      <div className="mapping__head">
        <span className="mono mapping__rule">{mapping.rule_id}</span>
        <span className="mapping__name">{RULE_NAME[mapping.rule_id] ?? mapping.rule_id}</span>
        <span className="mapping__spacer" />
        {mapping.technique_status === 'mapped' ? (
          mapping.technique_ids.map((technique) => (
            <span key={technique} className="mapping__tech mono">
              {technique}
            </span>
          ))
        ) : (
          <span className="mapping__tech mapping__tech--none" title={MAPPING_COPY.noTechnique}>
            no technique
          </span>
        )}
        {mapping.observation ? (
          <span className={`mapping__obs mapping__obs--${mapping.observation}`}>
            {mapping.observation === 'observed' ? MAPPING_COPY.observed : MAPPING_COPY.inferred}
          </span>
        ) : null}
      </div>
      <p className="mapping__why">{mapping.rationale ?? MAPPING_COPY.noRationaleV1}</p>
      <p className="mapping__limit">{mapping.limitation}</p>
      <div className="mapping__foot">
        <span className="mapping__ver mono">
          rule {mapping.rule_version}
          {mapping.mapping_version ? ` · ${mapping.mapping_version}` : ' · mapping version not in v1.0'}
        </span>
        <EvidenceIds ids={mapping.evidence_event_ids} {...handlers} />
      </div>
    </div>
  );
}

export function MappingList({
  mappings,
  basis,
  ...handlers
}: { mappings: MappingView[]; basis: Basis } & EvidenceHandlers) {
  return (
    <div className="mappinglist">
      <div className="mappinglist__basis">
        <BasisTag basis={basis} />
      </div>
      {mappings.map((mapping) => (
        <MappingRationale key={mapping.finding_id} mapping={mapping} {...handlers} />
      ))}
    </div>
  );
}
