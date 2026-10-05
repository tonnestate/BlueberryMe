# Privacy Compilation Layer — v0.4.2

BlueberryMe v0.4.2 turns repeated privacy inference into a compiled fast path.

The rule is:

> **Escalate once, compile the decision, enforce deterministically thereafter.**

This is inspired by the same architectural pattern used elsewhere in the TonnEstate stack: expensive discovery is not repeated indefinitely when the result can be represented as a bounded, versioned recipe.

## Escalation graph

```text
compiled recipe
      | hit
      +--------------------------> enforce
      | miss
      v
declared schema/catalog
      v
structural field inference
      v
detector callback
      v
agent suspicion
      v
cross-confirm / contradiction
      v
compile recipe
```

The default implementation is deliberately small. It does not require an LLM or a PII detector. Optional detectors can be injected.

## Compile key

A reusable recipe is addressed by an exact dispatch key over:

```text
dataset
+ schema fingerprint
+ policy version
+ purpose
+ operation
+ destination
```

There is no global recipe scan. A hot-path lookup is one exact encrypted-state lookup.

A policy change therefore invalidates old dispatch keys automatically. A different destination or purpose cannot reuse a recipe compiled for another context.

## Field evidence

A compiled field records:

- selected data class;
- disclosure action;
- provenance;
- evidence sources;
- contradictions.

Reference provenance values are:

```text
DECLARED
STRUCTURAL
DETECTED
AGENT_SUSPECTED
CROSS_CONFIRMED
UNKNOWN
```

Independent agreement can produce `CROSS_CONFIRMED`.

An agent hint is never authorization. If an agent-supplied suspicion would make the decision stricter, BBM may use it conservatively, but that recipe remains a `CANDIDATE` and is not promoted to the reusable hot path.

## Contradictions

If independent evidence disagrees, the compiler chooses the disclosure action with the stricter policy result and records the contradiction.

A contradicted recipe is not promoted to `PRIMARY`.

```text
declared: PERSON -> REVEAL
detector: HEALTH_DATA -> DENY

compiled action: DENY
role: CANDIDATE
reusable: false
```

This prevents stale or conflicting classification evidence from silently widening disclosure.

## Recipe roles

v0.4.2 introduces the lifecycle vocabulary:

- `PRIMARY` — exact-context recipe eligible for fast-path reuse;
- `CANDIDATE` — conservative result that still needs independent resolution;
- `FALLBACK` and `RETIRED` — reserved lifecycle roles for future portfolio evolution.

The reference runtime currently promotes only contradiction-free, independently grounded recipes to `PRIMARY`. It does not yet run a multi-recipe portfolio.

## Compiled egress

`EgressGate.protect_compiled_grid()` applies a compiled recipe directly to structured rows.

The gate still re-checks:

- active lease purpose;
- operation;
- destination;
- authenticated agent;
- lease scope;
- row limit;
- current policy version.

Unknown fields appearing after compilation are denied on the hot path. They do not receive an implicit new classification.

This gives a stable behavior for large result sets:

```text
cold path:
schema + evidence -> compile

hot path:
exact recipe lookup -> batch apply
```

## Scale objective

BlueberryMe should scale with privacy decisions, not raw source cardinality.

For a table with 20 fields and 10 million rows, classification should normally be performed on the schema/field surface, compiled once, and then reused across the rows. Aggregate workloads should still use source-side pushdown where possible.

## Non-goals

v0.4.2 does not claim:

- automatic semantic understanding of arbitrary free text;
- a complete enterprise data catalog;
- autonomous promotion of agent-only classifications;
- a distributed recipe registry;
- a multi-recipe bandit/portfolio scheduler.

Those can be added without changing the compile-once contract.
