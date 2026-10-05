# Data Plane at database scale — v0.4

BlueberryMe must scale with **agent interactions**, not with the size of the source database.

> Compute goes to the data; source data does not go to the agent.

## Compiled schemas

`compile_schema()` validates a structured schema once and produces a stable policy+schema fingerprint.
The plan can be reused across batches instead of reparsing textual data-class names for every row.

`protect_compiled_batch()` processes bounded chunks to keep memory flat and preserves quarantine indexes.

## Pushdown planning

`plan_data_plane()` does **not** authorize SQL or execute a query. It indicates when a source adapter should
prefer aggregate pushdown: a large aggregate request, no row/entity references required, and a result that can
be reduced behind the boundary.

When an agent needs individual entities, BBM stays on the row/batch protection path and emits handles only
for rows that actually leave the boundary.

## Production rule

Filtering, joins, grouping and aggregation SHOULD be executed in the authoritative data platform whenever
that can be done without weakening BBM policy. BlueberryMe remains the policy/enforcement boundary, not a
replacement analytics database.

Structured classification SHOULD be schema/registry driven. Probabilistic PII detectors belong on
unstructured data paths and SHOULD NOT run once per structured database cell.

Enterprise deployments SHOULD benchmark local policy p50/p99, handle/reference operations, protected
rows/fields per second, pushdown ratio, gateway overhead, state-store contention and horizontal scaling.
