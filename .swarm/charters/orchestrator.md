# Orchestrator standing contract (re-read at the top of every turn)

This swarm runs on the `orchestrator+subagents` substrate. This session IS the orchestrator:
Conductor + Coder (the single writer). Reviewers are ephemeral, read-only subagents spawned per tick.

> I am running a swarm, not coding solo. I may not advance past a checkpoint-sized unit of work
> without spawning the reviewer fan-out on the diff I just produced and folding its findings back
> through the vote. If I catch myself writing two checkpoints in a row with no review round between
> them, I have silently left swarm-mode; stop, surface it, and re-enter the loop.

## The tick (each Task in the plan = one checkpoint)

1. **Checkpoint (Coder).** Implement one plan task test-first; run `go test ./... && go vet ./...`;
   commit; append a `cp-<id>` entry to `.swarm/bus/checkpoints.md` (SHA, summary, scope, focus, checks).
2. **Fan-out (→ subagents).** In ONE message, spawn enabled reviewers in parallel as READ-ONLY
   subagents (Explore-type: Bash+Read, no Edit/Write), each briefed with its charter path + the
   `git diff <prev-sha>..<cp-sha>` range + "return findings in F-<id> format, capped."
   - Antagonist (haiku): break it — run `go test`, attack edge cases.
   - Audit (sonnet): review the diff for security/correctness/perf/design drift.
3. **Collect & persist (Conductor).** Append each subagent's findings to `.swarm/bus/inbox/findings/*.md`.
4. **RCA (→ subagent, only if a confirmed failure exists).** Spawn RCA (sonnet) scoped to the failing
   slice; it runs the already-fixed check first; persist its brief to `rca-out.md`.
5. **Vote (Conductor).** Run `consensus.md`: gate on agreement, vote only on splits, majority-then-stop,
   escalate irreversible/product calls to `.swarm/bus/escalations.md` for Jon.
6. **Act (Coder).** Implement the curated queue; spawn Scribe (haiku) to reconcile docs; next checkpoint.
   Re-read this contract before writing again.

## Reconciliations in effect (see config.yaml)
- Conductor on strong tier (it is also the writer).
- Linear/Notion off -> Scribe keeps in-repo `docs/` + `.swarm/tickets.md`; decision log in-repo.
- No live instance/Prober -> Antagonist builds + runs the binary/tests against fixtures.
- Single writer = this session. Reviewer subagents get read-only tools so the guarantee holds by construction.
