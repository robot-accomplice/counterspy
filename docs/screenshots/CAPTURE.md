# Regenerating the README screenshots

Rendered with [vhs](https://github.com/charmbracelet/vhs) (drives a real PTY, so the TUI
renders in color and can be screenshotted mid-run).

```sh
brew install vhs
go build -o /usr/local/bin/counterspy .
counterspy scan --json > /tmp/snap.json    # populated snapshot for the TUI shot
vhs docs/screenshots/scan.tape             # → docs/screenshots/scan.png
vhs docs/screenshots/tui.tape              # → docs/screenshots/tui.png
```

Notes:
- The first `vhs` run in a shell session can hit a transient `ttyd` connection race — just re-run it.
- The scan shot uses a longer `Sleep` to let collection finish; the TUI shot just waits for collection to render (Monitor rows show by default).
- Screenshots show a real machine (username, installed software). Regenerate on a demo machine if that's a concern.
