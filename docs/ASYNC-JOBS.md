# BBM/1 bounded asynchronous jobs

v0.3 supports asynchronous **single tool jobs** without lease renewal or a durable workflow engine.

## State machine

```text
QUEUED -> RUNNING -> COMPLETED -> RETRIEVED
   |         |           |
   |         +-> FAILED  +-> EXPIRED (result TTL)
   +-> CANCELLED
   +-> EXPIRED (deadline)
```

## Rules

1. The original lease is used only to authorize submission.
2. Submission converts handles into an encrypted job envelope containing source pointers or capsules.
3. The job gets a signed Job Intent and a maximum 24-hour deadline.
4. Execution checks current purpose and data-flow policy again.
5. SOURCE references compare `row_version` before use.
6. The target receives `job_id` as `idempotency_key` when its handler supports that parameter.
7. Raw results are encrypted in trusted state with TTL.
8. `get_result` creates a new lease and tokenises the response at retrieval time.
9. Retrieval removes the trusted raw result/envelope from normal job state.
10. Status and errors expose catalogue codes only.
11. A worker claims a job with an atomic conditional write and holds the claim for `run_lease_seconds` (default 60, capped at the deadline). A second worker gets `BBM_JOB_ALREADY_RUNNING` while the claim is live.
12. If a worker crashes, its claim expires and another worker takes the job over with the same `idempotency_key`.
13. A worker writes its outcome only if it still owns its claim. A late worker cannot overwrite a cancellation, expiry or takeover.
14. A completed result is delivered exactly once, also under concurrent retrieval.
15. Jobs record their owner (tenant, agent, purpose). Callers that pass an identity only see their own jobs.

Choose `run_lease_seconds` above the longest expected handler runtime. A handler that outlives its claim can be executed again by another worker; only the target's idempotency handling then prevents a duplicate side effect.

## Important limitation

BlueberryMe can avoid executing an already-completed job twice. It cannot guarantee exactly-once side effects in an external system after a worker crash unless that target honours `idempotency_key=job_id`.

## Not in v0.3

- multi-day orchestration;
- lease renewal;
- Temporal/Camunda integration;
- callbacks directly to an agent;
- HA queue semantics beyond the single-store worker claim above (heartbeats, fair scheduling, dead-letter queues).

Those remain provider/deployment concerns rather than BBM/1 core semantics.
