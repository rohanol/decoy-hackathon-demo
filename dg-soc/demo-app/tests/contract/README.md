`telemetry.schema.json` is a verbatim copy of `dg-soc/contracts/telemetry.schema.json`
from `m3/next-telemetry-contract` @ `eb2a94e` (PR #19, contract v1.2, not merged when
copied). The tests prefer `dg-soc/contracts/telemetry.schema.json` when it exists, and
fail if the two differ, so this copy cannot silently drift from the merged contract.
