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
		// Reconstruct the command from the 4th field onward — robust against a
		// username that recurs elsewhere in the line (cp-7 F-3/F-2).
		cmd := strings.Join(fields[3:], " ")
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

// BuildProcessEvidence emits evidence for processes holding a socket, attributing
// each to its full ancestry and argv.
//
// Identity is PID-ONLY. argv[0] is attacker-controlled (a process can exec with any
// argv[0]), so using it as Subject.Path would let a malicious listener alias its key
// onto an allowlisted app and be suppressed (cp-7 Audit F-1). argv[0] is kept as a
// display Fact. Safe real-path resolution is ticket T-4.
func BuildProcessEvidence(procs map[int]*Proc, listeners map[int][]string) []model.Evidence {
	var ev []model.Evidence
	for pid, descs := range listeners {
		p := procs[pid]
		if p == nil {
			continue
		}
		listening := false
		for _, d := range descs {
			if strings.Contains(d, "LISTEN") {
				listening = true
			}
		}
		facts := map[string]string{
			"argv":     p.Cmd,
			"argv0":    firstField(p.Cmd),
			"ancestry": ancestry(procs, pid),
			"ports":    strings.Join(descs, ", "),
		}
		summary := "process has an active network connection"
		if listening {
			facts["listener"] = "true" // only a real LISTEN socket (cp-7 QA F-1)
			summary = "process holds a network listener"
		} else {
			facts["net"] = "connection"
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{PID: pid},
			Kind:    model.KindProcess,
			Summary: summary,
			Weight:  wListener,
			Facts:   facts,
		})
	}
	return ev
}

func firstField(cmd string) string {
	if f := strings.Fields(cmd); len(f) > 0 {
		return f[0]
	}
	return ""
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
