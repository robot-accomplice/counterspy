# Consensus: self-organize, collaborate, vote

The swarm decides as much as it can on its own and only brings the human genuine forks in the road.
This file defines how findings become decisions, when the swarm votes, and what crosses the line into
"ask the human." The Conductor runs this protocol; the reviewers participate.

The guiding tension: you want the *collective* judgment of several independent reviewers (that's the
whole point of a swarm), but naive debate and unanimous polling are expensive and can even make things
worse — homogeneous agents will happily reinforce a shared wrong answer, and unbounded debate just
burns tokens. So the protocol leans on **independent findings first, structured voting only when
needed, and hard caps** so collaboration never spirals.

## Stage 1 — Self-direct effort (no chatter)

This is the "self-organize" stage, but be precise about what self-organization means here, because the
naive version (agents negotiating who does what) is a known token sink that often costs more than it
saves. In this swarm, roles are **fixed** and the Conductor assigns *scope*; self-organization is each
session **independently deciding how much effort a change warrants** and working without coordinating.
That's the form of autonomy that helps; open-ended role negotiation is the form that hurts.

- Each reviewer judges effort from the checkpoint's `focus` and `scope`: a one-line config change gets
  a glance; a change to auth or a hot path gets the full checklist.
- Reviewers work **independently and in parallel** — they do not read each other's findings yet.
  Independence is what makes the later vote meaningful; if they see each other first, they anchor and
  you lose the diversity that catches bugs.

> If you genuinely want richer self-organization — reviewers claiming or declining scope, or electing
> which specialist to spin up — add a brief "claim" round on the bus before review. It costs a round of
> tokens; enable it only when the work is heterogeneous enough that fixed scope assignment is leaving
> the right reviewer off the right change.

## Stage 2 — Collect & cluster

The Conductor gathers all findings for the checkpoint and clusters them:

- **Dedupe.** Multiple reviewers flagging the same line collapse into one issue (with the union of
  their reasoning). Agreement is recorded — it raises confidence and usually removes the need to vote.
- **Cluster by locus.** Findings touching the same code or the same decision are grouped so the vote
  is about a *decision*, not a pile of overlapping notes.
- **Pre-score.** Each issue carries a severity (crit/high/med/low) and a confidence (high/med/low)
  derived from the findings and how many independent reviewers raised it.

## Stage 3 — Decide whether to vote (confidence gate)

Voting is not free, so the swarm only votes when it would change the outcome:

- **Skip the vote** when reviewers **agree** and confidence is **high** — e.g. everyone who looked
  flags the same crit bug, or nobody raised anything above "low." Agreement is its own signal; spending
  a debate round to confirm what's already unanimous is pure waste. These flow straight to a decision.
- **Hold a vote** only when there's a real split: reviewers **disagree** (one says ship, one says
  block), or severity/confidence is **mixed**, or the fix involves a **trade-off** (e.g. correctness
  vs. latency) with no obviously dominant option.

## Stage 4 — Vote (only when gated in)

A vote is a single structured round, not an open debate. Each participating reviewer casts:

```
vote: <fix-now | defer | wont-fix | needs-human>
option: <which proposed option, if several>
confidence: <high | med | low>
reason: <=1 sentence
```

Rules that keep it cheap and honest:

- **One round by default.** Reviewers cast once. A *second* round happens only if the first is a true
  tie or split, and only the dissenters speak (they get one chance to change minds with new
  information — not to restate). **Hard cap: 2 rounds.** After that it's a `needs-human` escalation.
- **Majority-then-stop.** As soon as a majority is reached on an option, stop collecting — don't poll
  roles that can't change the result.
- **Weight by relevance, lightly.** The role closest to the issue gets a slightly heavier voice
  (Audit on a security finding, QA on a behavioral one), but no single role has a veto except the
  human. Record the weighting used.
- **Confidence-weighted, not just headcount.** A high-confidence minority against a low-confidence
  majority is exactly the situation to escalate rather than steamroll — diversity of judgment is the
  asset, so don't let a thin majority bury a strong dissent.
- **The Coder doesn't vote on its own work** beyond flagging feasibility — it's not a neutral judge of
  whether its change is sound. It can supply a feasibility/cost note that informs the vote.

## Stage 5 — Resolve or escalate

After the gate/vote, every issue lands in exactly one bucket:

- **Auto-resolve → Coder queue.** Agreed or clear-majority `fix-now`/`defer`/`wont-fix` items become
  queue entries (fix-now) or tickets (defer) with the tally attached. No human needed.
- **Escalate → human.** Anything that is `needs-human`, an unresolved split after 2 rounds, a
  high-confidence dissent against the majority, or a decision that is **irreversible or product-level**
  (schema migration, data deletion, money movement, public API change, security trade-off, or a
  scope/priority call the swarm can't source from the code). The swarm informs; the human decides.

The escalation threshold is deliberately set so the human sees **decisions, not noise** — if the swarm
escalates everything, it's failed at its job; if it escalates nothing irreversible, it's overstepping.

### Escalation / options memo (the only human-facing artifact)

Written by the Conductor to `.swarm/bus/escalations.md`. Keep it short — it's a decision aid, not a
report. Lead with the recommendation so a busy human can rubber-stamp the common case in one read.

```
## ESC-<id>  cp-<id>  <iso-timestamp>
decision needed: <the single question, in one line>
recommendation: <the swarm's preferred option and why, 1-2 sentences>
options:
  A) <option> — pros: <...>  cons: <...>  who favors: <roles>
  B) <option> — pros: <...>  cons: <...>  who favors: <roles>
dissent: <the strongest argument against the recommendation, named — or "none">
reversible: <yes/no — and the cost of being wrong>
vote tally: <e.g. 2 fix-now (Audit, QA, high conf) vs 1 defer (RCA, low conf)>
```

Two things make this memo trustworthy: it **always surfaces the dissent** (so the human isn't shown a
false consensus), and it **states reversibility** (so the human knows how much the decision actually
matters). A swarm that hides its disagreements to look decisive is worse than no swarm.

## Worked example

QA finds a crash on empty input (F-12, crit, high conf). Audit independently flags the same code path
plus a missing authz check nearby (F-13, high, high conf). Conductor clusters: F-12 and the crash
half of F-13 dedupe into one issue — **unanimous, high confidence → no vote**, straight to RCA then
the Coder queue. The authz finding is new and only one reviewer saw it; severity is high but the fix
has a latency cost, and RCA suspects it may be enforced upstream (med conf) — **mixed → vote.** Round
one: Audit `fix-now/high`, QA abstains (out of lane), RCA `defer/med` pending confirmation. No
majority for an irreversible-ish security change with live dissent → **escalate** with a two-option
memo: fix now (Audit) vs. confirm upstream enforcement first (RCA), recommendation = confirm-first
because it's cheap and reversible, dissent recorded. The human picks in one read.
