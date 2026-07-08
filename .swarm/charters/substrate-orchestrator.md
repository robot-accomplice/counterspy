# Substrate: orchestrator + subagents

Everything else in this skill assumes the **multi-terminal** substrate: one persistent, human-launched
Claude Code session per role, each in its own git worktree, woken by the blocking `wait-for-tick.sh`
watcher. This file describes the other substrate — selected by `substrate: orchestrator+subagents` in
`config.yaml` — where a **single persistent session (the orchestrator)** spawns **ephemeral subagents**
(via the Task/Agent tool) to play the reviewer roles each tick. `setup.md` → "Adapting the substrate"
introduces it in one paragraph; this file is the operating manual.

If your config says `orchestrator+subagents`, operate from *this* file, not the watcher sections. The
single-writer rule, the bus formats (`coordination.md`), the consensus protocol (`consensus.md`), and
the caps (`token-control.md`) are all **unchanged** — only *how sessions are spawned and woken*
changes. But that change is mechanical enough that running the wrong mode is how a swarm quietly stops
being a swarm. **The single biggest risk here is drift: the orchestrator reverting to solo, serial
coding and never spawning the reviewers.** This file exists mostly to prevent that.

## Three facts that change everything

**1. A tick is a fan-out of Task/Agent calls — there is nothing to "wake."** There are no standing
sessions and no watcher. Each reviewer role becomes one subagent invocation whose prompt *is* that
role's launch prompt from `roles.md` (charter + read-only boundary) plus the tick's scope. Because the
reviewers are independent, **spawn them in a single message with multiple Task tool-uses so they run
concurrently** — that is the "parallel review" stage, realized. Give each subagent **read-only tools**
(an Explore-type agent, or Task with Write/Edit withheld) so the single-writer guarantee holds by
construction, not by promise. Do **not** set up or call `wait-for-tick.sh`; the "idle at zero tokens"
machinery is irrelevant when there are no persistent sessions to idle.

**2. Subagents are stateless. The bus is the only memory.** An ephemeral subagent remembers nothing
between ticks — not the last checkpoint, not its own prior findings, not what a sibling subagent found.
So every tick you re-brief a *fresh* subagent that reloads its charter from `.swarm/charters/` and reads
the scoped diff. Two consequences:

- Each subagent prompt must name the exact things to read — its charter path and the `git diff
  <prev-sha>..<cp-sha>` range — because nothing carries over from last tick.
- The orchestrator must **persist each subagent's returned findings to the bus** (`findings/qa.md`,
  `findings/audit.md`, etc.) in the standard `F-<id>` format, because next tick's subagents are new and
  can only see history that lives on disk. The subagent's returned message is the finding; writing it to
  the bus is what makes it durable and reviewable.

**3. The orchestrator IS the Conductor and the Coder — and that's the trap.** In this substrate the
orchestrator is the main loop that drives every Task call, runs consensus, and gatekeeps escalations
(the Conductor's job) *and* holds the pen as the single writer (the Coder's job). Collapsing the two
persistent roles into one context is efficient, but it removes the thing that keeps the multi-terminal
version honest: there, the operating protocol lives inside each session's standing launch prompt, so a
session can't forget what it is. As the sole orchestrator you have **no standing contract** — nothing
structurally stops you from writing checkpoint after checkpoint and never spawning the reviewers.
Because the Conductor role is now also the writer, it runs on the **strong tier** here (e.g.
`conductor: opus`), not the cheap tier the multi-terminal default assumes — reconcile this in
`config.yaml` rather than treating it as a misconfiguration (see `setup.md` → config reconciliation).

## The orchestrator's standing obligation

Re-read this at the top of every turn. It is the contract that the multi-terminal launch prompts give
each reviewer for free, and that you — as the single driver — have to hold yourself:

> I am running a swarm, not coding solo. I may not advance past a checkpoint-sized unit of work without
> spawning the reviewer fan-out on the diff I just produced and folding its findings back through the
> vote. If I catch myself writing two checkpoints in a row with no review round between them, I have
> silently left swarm-mode; stop, surface it, and re-enter the loop.

Persist this to `.swarm/charters/orchestrator.md` at setup, so any session that later *resumes* the
swarm re-reads it (see "Resuming" below).

## A tick, mapped to Task/Agent calls

1. **Checkpoint (you, as Coder).** Implement one reviewable unit; run the fast local checks; commit;
   append a checkpoint to `.swarm/bus/checkpoints.md` in the standard format (`cp-<id>`, commit SHA,
   summary, scope, focus). No pasted code.
2. **Fan-out (you → reviewer subagents).** In one message, spawn the enabled reviewers in parallel —
   Antagonist, Audit, and (if a live instance is up) Prober. Each prompt = its `roles.md` launch prompt
   + `git diff <prev-sha>..<cp-sha>` scope + "return findings in the `F-<id>` format, capped per
   `token-control.md`." Read-only tools only.
3. **Collect & persist (you, as Conductor).** Take each subagent's returned findings, dedupe and
   cluster per `consensus.md` Stage 2, and append them to the reviewers' `findings/*.md` files so the
   trail survives the subagents that produced it.
4. **RCA (you → RCA subagent).** For each confirmed failure, spawn an RCA subagent scoped to the
   failing slice. It runs the **already-fixed / in-flight check first** (see `roles.md`), then returns
   a fix brief or an `already-addressed:` note. Persist to `rca-out.md`.
5. **Vote (you, as Conductor).** Run the consensus protocol yourself: gate on agreement, vote only on
   genuine splits, majority-then-stop, escalate irreversible/product calls to the human via
   `escalations.md`. You are the tally-keeper; you do not get to vote away the human's calls.
6. **Act (you, as Coder).** Implement the curated queue; spawn a Scribe subagent to reconcile
   docs/tickets and post its `synced:` line; emit the next checkpoint. **Re-read the standing obligation
   before you start writing again.** Loop.

## Cost notes specific to this mode

Most `token-control.md` levers are free here: subagents already have isolated context (lever 2), you
already scope their reads to the diff (lever 3), and they cost nothing between ticks because they don't
exist between ticks (lever 4, for free). The one *new* cost is **re-briefing overhead** — because
subagents are stateless, you re-send each charter every tick. Keep the charters lean and point to files
in `.swarm/charters/` rather than inlining them, and rely on the bus tail for history instead of
re-summarizing it into each prompt.

## Resuming an existing swarm in this mode

When you are invoked into a repo that already has a `.swarm/` directory, **you are resuming, not setting
up.** Do not re-scaffold, re-create worktrees, or re-run the dry-run tick. Instead:

1. **Read `config.yaml` first** — it, not this skill's defaults, is the source of truth for this swarm
   (substrate, live roster, model tiers, integrations). Reconcile any drift explicitly (`setup.md`).
2. **Reconstruct state from the bus tail** — the last checkpoint (`cp-<id>`/SHA), open findings not yet
   resolved, the current Coder queue, and ticket/milestone state. The bus is replayable precisely so a
   fresh driver can pick it up.
3. **Adopt the orchestrator role** and re-read the standing obligation above (and
   `.swarm/charters/orchestrator.md` if present).
4. **Re-enter the loop from the last checkpoint** — if that checkpoint was never reviewed, run its
   review fan-out *before* producing anything new. Never let "resume" become "start writing solo from
   wherever the code happens to be."
