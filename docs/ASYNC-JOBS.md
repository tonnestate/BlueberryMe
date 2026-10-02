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

## Important limitation

BlueberryMe can avoid executing an already-completed job twice. It cannot guarantee exactly-once side effects in an external system after a worker crash unless that target honours `idempotency_key=job_id`.

## Not in v0.3

- multi-day orchestration;
- lease renewal;
- Temporal/Camunda integration;
- callbacks directly to an agent;
- distributed worker leasing/HA queue semantics.

Those remain provider/deployment concerns rather than BBM/1 core semantics.
