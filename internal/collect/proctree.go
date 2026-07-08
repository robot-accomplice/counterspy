package collect

import (
	"os/exec"
	"strconv"
	"strings"

	"counterspy/internal/model"
)

const wListener = 2

type Proc struct {
	PID, PPID int
	User      string
	Cmd       string // full command line (argv)
}

// ParsePs parses `ps -axo pid,ppid,user,command` output.
func ParsePs(b []byte) map[int]*Proc {
	out := map[int]*Proc{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(ln)
		if len(fields) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		cmd := strings.TrimSpace(strings.SplitN(ln, fields[2], 2)[1])
		out[pid] = &Proc{PID: pid, PPID: ppid, User: fields[2], Cmd: cmd}
	}
	return out
}

// ParseLsof maps a PID to human listener descriptions.
func ParseLsof(b []byte) map[int][]string {
	out := map[int][]string{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		out[pid] = append(out[pid], strings.Join(fields[8:], " "))
	}
	return out
}

// ancestry walks parent links up to launchd (pid 1) and renders the chain.
func ancestry(procs map[int]*Proc, pid int) string {
	var chain []string
	seen := map[int]bool{}
	for p := procs[pid]; p != nil && !seen[p.PID]; p = procs[p.PPID] {
		seen[p.PID] = true
		name := p.Cmd
		if sp := strings.Fields(p.Cmd); len(sp) > 0 {
			name = sp[0]
		}
		chain = append([]string{name}, chain...)
		if p.PID == 1 {
			break
		}
	}
	return strings.Join(chain, " -> ")
}

// BuildProcessEvidence emits evidence for processes that hold listeners,
// attributing each to its full ancestry and argv.
func BuildProcessEvidence(procs map[int]*Proc, listeners map[int][]string) []model.Evidence {
	var ev []model.Evidence
	for pid, descs := range listeners {
		p := procs[pid]
		if p == nil {
			continue
		}
		facts := map[string]string{
			"listener": "true",
			"argv":     p.Cmd,
			"ancestry": ancestry(procs, pid),
			"ports":    strings.Join(descs, ", "),
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{PID: pid, Path: execPath(p.Cmd)},
			Kind:    model.KindProcess,
			Summary: "process holds a network listener",
			Weight:  wListener,
			Facts:   facts,
		})
	}
	return ev
}

// execPath best-effort extracts the on-disk binary path from argv so process
// evidence can correlate with codesign/persistence evidence by Path.
func execPath(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "/") {
		return fields[0]
	}
	return "" // interpreter without absolute path — correlate by PID only
}

// CollectProcesses runs ps + lsof (I/O edge).
func CollectProcesses() ([]model.Evidence, error) {
	psb, err := exec.Command("ps", "-axo", "pid,ppid,user,command").Output()
	if err != nil {
		return nil, err
	}
	lsb, _ := exec.Command("lsof", "-i", "-nP").Output() // may be partial without root
	return BuildProcessEvidence(ParsePs(psb), ParseLsof(lsb)), nil
}
