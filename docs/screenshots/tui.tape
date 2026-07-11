# Prep: counterspy scan --json > /tmp/snap.json   (a populated snapshot to drive the TUI)
# Regenerate: vhs docs/screenshots/tui.tape
Output "/tmp/throwaway.gif"
Set FontSize 15
Set Width 1600
Set Height 1000
Set Padding 24
Set Theme "Dracula"
Hide
Type "clear"
Enter
Show
Type "counterspy tui --from /tmp/snap.json"
Sleep 500ms
Enter
Sleep 2s
Type "m"
Sleep 900ms
Screenshot "docs/screenshots/tui.png"
Type "Q"
