# README screenshots — capture guide

Drop the captured images in this directory with the exact filenames below; the README
references them by these names. Re-capture with the same recipe when the UI changes.

## Recommended terminal setup
- Size: **~110×34** or larger (the egress tree + detail strip need width and height).
- **Dark** background; a monospace font with box-drawing + block glyphs so the sparklines
  (`▁▂▃▄▅▆▇█`) and tree markers (`▸ ▾ └`) render cleanly (SF Mono, JetBrains Mono, or a
  Nerd Font all work).
- Run under **`sudo`** so the views are populated with real data (TCC + full process/egress
  visibility). Redact any hostname/path you'd rather not publish before capturing.

## Shots

| File | Command | What to frame |
|------|---------|---------------|
| `scan.png` | `sudo counterspy scan` | The ranked report — the executive summary line + a couple of actionable (Quarantine/Investigate) findings with their evidence. |
| `tui.png` | `sudo counterspy tui` | The master-detail triage view with a finding **selected** so the right-hand DETAIL pane shows its evidence; the footer keybar visible. |
| `egress.png` | `sudo counterspy egress` | The live egress tree with a couple of apps, **one expanded** to show its PID instances → port/protocol connections; concern colors + the footer visible. |

## Optional
- `egress.gif` — a short (~5–8s) screen recording of navigating the egress tree
  (expand/collapse, sort). If you provide it I'll embed it as the lead visual.

## Handing them over
Either commit the files to this directory on the `docs/readme-screenshots` branch, or just
share the PNGs and I'll place, caption, and wire them into the README, then open the PR.
