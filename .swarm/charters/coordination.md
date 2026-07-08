# Coordination

How sessions talk to each other without burning tokens or stepping on the single-writer rule. The
model is **hybrid**: a fast file-based bus for inter-session messages, plus durable work items in
Linear and durable knowledge in Notion (maintained only by the Scribe).

## Why hybrid

The bus is for *ephemeral, fast* coordination — "here's a checkpoint," "here are my findings," "here's
the queue." It lives in the repo, is append-only, costs nothing to read a slice of, and is trivially
truncatable. Tickets and docs are for *durable* state that must outlive any session and be visible to
humans — the work backlog (Linear) and the knowledge vault / decision record (Notion). Putting
ephemeral chatter in tickets would spam your tracker; putting durable decisions only in the bus would
lose them at the next compaction. So: bus for motion, Linear/Notion for memory.

## Session identity and naming

Every session names itself so that humans and the other sessions can tell, at a glance, which project
it belongs to, what role it plays, and that it is part of a swarm. This matters once several
terminals, worktrees, and bus entries are in flight — an unnamed session is an anonymous source of
edits and messages, which is exactly what you don't want when debugging the swarm itself.

**Canonical identity:** `swarm/<project>/<role>[/<instance>]`

- `swarm/` — the fixed label marking this as a swarm member.
- `<project>` — a short slug for the repo/project (e.g. `checkout-api`).
- `<role>` — `coding`, `antagonist`, `rca`, `audit`, `scribe`, `conductor`, or a specialist slug.
- `<instance>` — optional, only when two of the same role run (e.g. `audit/security`, `audit/perf`).

Each session establishes its identity on launch and uses it consistently:

- **Self-declaration.** The first thing a session does is state its identity to itself and on the bus:
  append a one-line `joined: swarm/<project>/<role>` entry to `.swarm/bus/log/roster.md`, so the roster
  is visible in one place.
- **Bus authorship.** Every bus entry is signed with the role tag already baked into the formats
  below (`[QA]`, `[AUDIT]`, etc.); the full identity is implied by which inbox file it writes to.
- **Git footprint.** The Coder commits with the identity in the author/trailer
  (`Co-authored-by: swarm/<project>/coding`) and works on a branch named `swarm/<project>/work`, so
  the swarm's commits are attributable and easy to filter.
- **Worktree path.** Each worktree directory is named for the identity (see `setup.md`):
  `../<project>-swarm/<role>`, so `pwd` alone tells a session who it is.
- **Terminal/window title.** Where the environment allows it, set the terminal title to the identity
  so a human scanning their windows can find the right session instantly. The launch prompt instructs
  each session to print its identity as its first line of output.

`config.yaml` records the `project` slug once so every role derives the same names rather than
each session inventing its own.

## The file bus

Lives at `.swarm/bus/` inside the repo (or a shared path). Layout:

```
.swarm/
├── config.yaml              # substrate, roles enabled, model tiers, caps, integration toggles
├── charters/                # the reference docs, copied in so each session can read them locally
│   ├── roles.md
│   ├── coordination.md
│   ├── consensus.md
│   ├── token-control.md
│   ├── substrate-orchestrator.md  # only if substrate: orchestrator+subagents
│   ├── live-instance.md           # only if running a live instance
│   └── orchestrator.md            # only if orchestrator+subagents: the standing anti-drift contract
├── scripts/
│   └── wait-for-tick.sh     # blocking bus watcher — the "wake" mechanism (multi-terminal only)
└── bus/
    ├── checkpoints.md       # Coder appends; the append wakes the Conductor
    ├── instance.md          # live system-under-test registry (only if running a live instance)
    ├── inbox/
    │   ├── coding.md        # Conductor → Coder: the curated, prioritized queue (wakes Coder)
    │   ├── rca-in.md        # Conductor → RCA: confirmed failures (wakes RCA)
    │   ├── rca-out.md       # RCA → Coder: fix briefs (or "already-addressed:" notes)
    │   ├── antagonist-wake.md  # Conductor → QA: scope assignment (wakes QA)
    │   ├── audit-wake.md       # Conductor → Audit: scope assignment (wakes Audit)
    │   ├── scribe-wake.md      # Conductor → Scribe: resolved-vote summary (wakes Scribe)
    │   └── findings/        # one file per reviewer so parallel writers never collide
    │       ├── qa.md        # Antagonist → Conductor: raw findings
    │       ├── audit.md     # Audit → Conductor: raw findings
    │       └── prober.md    # Prober → Conductor: live-instance findings (only if running one)
    ├── escalations.md       # Conductor → human: options memos
    └── log/
        └── roster.md        # each session appends its "joined:" line on launch
```

> **Substrate note.** The wake files (`*-wake.md`) and `wait-for-tick.sh` are the **multi-terminal**
> mechanism. Under `orchestrator+subagents` there is no watcher: the orchestrator drives the tick as a
> fan-out of Task calls and *persists* each subagent's returned findings into `findings/*.md` itself, so
> the same formats and files still hold — they're just written by the orchestrator, not by a standing
> reviewer session. See `references/substrate-orchestrator.md`.

**Why per-reviewer findings files:** QA and Audit run in parallel, and two processes appending to one
file can interleave or clobber. Each reviewer owns its own file under `findings/`; the Conductor reads
both during triage. This is cheaper and safer than any locking scheme.

**Rules of the bus.**

- **Append-only.** Never rewrite history; add a new entry. This makes "what's new since my last tick"
  a cheap tail read instead of a full re-read, and keeps an audit trail.
- **One concern per entry.** A finding, a checkpoint, a brief — not a wall.
- **Always stamp the checkpoint.** Every entry names the `cp-id` (checkpoint id / commit SHA) it
  relates to, so stale entries are obvious and ignorable.
- **Read the tail, not the file.** When you wake, read entries newer than your last-seen `cp-id`. The
  Conductor records each role's last-seen marker so nobody re-reads resolved ticks.
- **No code in the bus.** Reference the diff (`git diff A..B -- path`); never paste large source.

### Message formats

Keep these tight — the format *is* the token-control mechanism.

**Checkpoint** (Coder → `checkpoints.md`):
```
## cp-<id>  <commit-sha>  <iso-timestamp>
summary: <one paragraph, what changed and why>
scope: <space-separated paths touched>
focus: <what you most want eyes on — e.g. "the retry logic in client.py">
checks: <build/tests/lint status you already ran>
```

**Finding** (QA → `findings/qa.md`, Audit → `findings/audit.md`):
```
### F-<id>  cp-<id>  [QA|AUDIT]  sev:<crit|high|med|low>  conf:<high|med|low>
where: <file:line or surface>
issue: <one or two sentences>
repro|why: <minimal repro for QA, or rationale for Audit>
suggest: <concrete suggested change, if obvious — optional>
```

**Fix brief** (RCA → `rca-out.md`):
```
### B-<id>  cp-<id>  for:CODER  sev:<...>  conf:<...>
cause: <root cause in 1-2 sentences>
where: <exact location>
fix: <the minimal change that addresses it>
blast: <what else this could affect>
```

**Queue item** (Conductor → `coding.md`):
```
### Q-<rank>  refs:<F-/B- ids>  decision:<fix-now|defer>  votes:<tally if one was held>
do: <imperative one-liner for the Coder>
```

**Escalation / options memo** (Conductor → `escalations.md`): see `consensus.md` for the exact
template — this is the only artifact written *for the human*, so it gets a little more prose.

## Linear (tickets)

The Scribe is the only writer to Linear. Mapping:

- A **voted "fix-now" or "defer" issue** that's more than a one-tick fix becomes a Linear issue. One-
  tick trivia stays on the bus and never becomes a ticket — don't pollute the tracker.
- Ticket **title** = the issue summary; **description** = cause + suggested fix + originating `cp-id`
  and finding ids; **labels** = severity and the role that found it; **status** tracks the work
  (Backlog → In Progress when the Coder picks it up → Done at the checkpoint that resolves it).
- The Scribe transitions tickets in response to checkpoints and vote outcomes, not on its own
  initiative — the bus is the source of truth, Linear mirrors it.

If the Linear MCP is connected, use it. If not, the Scribe keeps `.swarm/tickets.md` in the same shape
and notes that external sync is pending, so nothing is lost.

## Notion (knowledge vault + docs)

The Scribe is the only writer to Notion. It maintains:

- **Decision log** — every vote outcome with the chosen option, the alternatives, the tally, and the
  recorded dissent. This is the swarm's institutional memory; it's what makes "why did we do it this
  way" answerable three weeks later.
- **Knowledge vault** — durable facts the swarm keeps rediscovering (architecture notes, gotchas,
  environment quirks, runbooks). When a reviewer learns something the hard way, it goes here so the
  next tick doesn't re-pay for the lesson.
- **Living docs** — README/architecture/runbook updates that track the code.

If the Notion MCP is connected, use it. If not, mirror the same structure under an in-repo `docs/` and
note that external sync is pending.

## Keeping the record from drifting

The single biggest failure of a doc-keeping role is silent drift — code moves, docs don't. Two guards:

1. The Scribe runs **every tick**, reconciling against the checkpoint, so drift is at most one tick
   wide.
2. The Scribe posts a `synced: <what>` line to the bus; if the Conductor sees a resolved checkpoint
   with no matching `synced:` line, it re-wakes the Scribe before closing the tick.
