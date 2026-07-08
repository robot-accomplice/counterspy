# Token control

A swarm can spend an order of magnitude more tokens than a single session — multiple sessions, each
with its own context, all reading and reasoning. That's the price of higher review pressure. The job
of this file is to make sure you pay for *signal*, not for sessions re-reading files and restating
each other. The setting here is **maximum savings**: every technique below is on by default.

Treat token spend as the primary thing to manage. In Anthropic's own multi-agent measurements, token
volume explained the large majority of performance variance — which cuts both ways: spend is what
buys quality, so the goal isn't to starve the swarm but to make sure every token does work.

## The levers (default-on)

### 1. Model tiering — spend reasoning where it writes
The Coder runs on the strongest tier because its output is code that everyone else reviews; a mistake
there is expensive downstream. Reviewers run cheaper: a Haiku-class Antagonist and Scribe, a
Sonnet-class RCA and Audit. The Conductor is coordination, not reasoning — cheapest tier. This single
choice is usually the biggest saving, because the expensive model only runs on the writing path, not
on five parallel review streams.

### 2. Context isolation — exchange findings, never transcripts
Each session keeps its own window and the sessions communicate through the bus. A finding is a few
lines; a transcript or a pasted file is thousands of tokens. **No session ever sends another its raw
context.** This is also why reviewers reference `git diff A..B` instead of pasting code — the reader
fetches exactly the lines they need.

### 3. Scoped reads — diff, not repo
Reviewers read the **diff** for the checkpoint, not the whole repository. RCA reads only the failing
slice and its immediate dependencies. The Conductor tells each reviewer the exact scope on wake, so
nobody "just has a look around." Re-reading unchanged files across ticks is the quietest, largest leak
in a long-running swarm.

### 4. Watcher-driven ticks — no model-side polling
A session waits for its next tick by running the blocking `wait-for-tick.sh` watcher as a shell
command. While it blocks, **the model spends zero tokens** — there is no "check if anything changed"
*model* loop, which is the thing that would burn tokens producing nothing. The waiting happens in the
shell (an `inotifywait`/`fswatch` event, or a cheap low-frequency mtime poll as fallback), and the
model only resumes when the bus actually changes. Be honest about what this is: it is event-like
idling, not a magic cross-process signal — independent Claude sessions can't wake each other, so the
watcher is the bridge. The cost to keep a session "available" is therefore a blocked shell process,
not tokens.

### 5. Sparse / delta messaging — only what's new
The bus is append-only and every session reads only entries newer than its last-seen checkpoint. Only
*novel* information propagates each tick; unchanged context is never re-sent or re-read. When a
reviewer has nothing new to add for a checkpoint, it posts a single `nil: cp-<id>` line rather than
re-summarizing.

### 6. Confidence-gated debate — agreement skips the vote
If reviewers already agree, there is no vote (see `consensus.md`). Debate rounds are the most
expensive thing the swarm can do, so they happen only on genuine splits, and even then they're capped
at 2 rounds before escalating. Don't pay for deliberation on a settled question.

### 7. Majority-then-stop — don't poll the settled
Once a vote reaches a majority, stop collecting. Roles that can't change the outcome aren't asked.

### 8. Hard caps everywhere
Caps are what keep a bad tick from becoming an expensive one. Defaults (tune in `config.yaml`):

| Cap | Default | Why |
|-----|---------|-----|
| Max active reviewers per tick | 4 | Beyond this, coordination cost outruns bugs caught. |
| Max findings per reviewer per tick | 10 | Forces prioritization; a 50-item dump is noise. |
| Max length per bus message | ~200 words | A finding that needs an essay should be a ticket. |
| Max debate rounds | 2 | Then escalate — unbounded debate is the classic token sink. |
| Max checkpoint diff for one tick | ~400 lines | Bigger changes get split into multiple checkpoints. |
| RCA effort budget per failure | bounded | Post leading hypothesis at low confidence rather than spelunking forever. |

### 9. Compaction & the durable record
Long sessions will hit context limits. Two defenses: the **Scribe** persists decisions and knowledge
to Notion/Linear every tick, so the swarm's memory lives *outside* any one window and survives a
compaction; and the **bus** is the replayable source of truth, so a restarted session rebuilds state
from the tail of the bus rather than from a giant in-context history. Never rely on a session
remembering — rely on the record.

### 10. Right-size the swarm
The cheapest reviewer is the one you didn't start. Run the minimum set that covers the risk: for a
small change, Coder + Antagonist + Audit may be enough; bring in RCA when something actually fails,
specialists only for risky surfaces. 2–4 active reviewers is the sweet spot the research and practice
converge on.

## What *not* to skimp on
Token discipline is about removing waste, not capability. Don't tier the Coder down to save money —
its mistakes are the most expensive thing in the system. Don't cap findings so hard that a real bug
gets dropped — the cap is for noise, and a crit finding always gets through. Don't suppress dissent to
avoid a vote — a cheap wrong answer is the most expensive outcome of all. Spend freely on the writing
path and on genuine disagreement; economize on everything that merely re-states what's already known.

## A rough mental model of where tokens go
Per tick, in descending spend: the Coder implementing (expensive tier, real reasoning) → RCA/Audit
reasoning over a diff (mid tier) → QA generating cases (cheap tier, but can be high volume) → Conductor
and Scribe coordinating/recording (cheap tier, small). If your bill is dominated by reviewers rather
than the Coder, something is wrong — usually unscoped reads (levers 3/5) or polling (lever 4). Check
those first.
