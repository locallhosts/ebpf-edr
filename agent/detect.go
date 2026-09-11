package main

import (
    "fmt"
    "strings"
    "sync"
    "time"
)

// Alert is what the detection engine emits when a heuristic fires.
type Alert struct {
    Time        time.Time `json:"time"`
    Severity    string    `json:"severity"`
    Technique   string    `json:"mitre_technique"`
    Rule        string    `json:"rule"`
    Pid         uint32    `json:"pid"`
    Ppid        uint32    `json:"ppid"`
    Comm        string    `json:"comm"`
    Description string    `json:"description"`
}

type processState struct {
    execComm  string
    execArgv0 string
    execTime  time.Time
}

type Detector struct {
    mu    sync.Mutex
    procs map[uint32]processState
    ttl   time.Duration

    onAlert func(Alert)
}

func NewDetector(onAlert func(Alert)) *Detector {
    d := &Detector{
        procs:   make(map[uint32]processState),
        ttl:     30 * time.Second,
        onAlert: onAlert,
    }
    go d.reaper()
    return d
}

func (d *Detector) reaper() {
    t := time.NewTicker(10 * time.Second)
    for range t.C {
        d.mu.Lock()
        now := time.Now()
        for pid, st := range d.procs {
            if now.Sub(st.execTime) > d.ttl {
                delete(d.procs, pid)
            }
        }
        d.mu.Unlock()
    }
}

var shellBinaries = map[string]bool{
    "/bin/sh": true, "/bin/bash": true, "/bin/dash": true, "/bin/zsh": true,
    "/usr/bin/python3": true, "/usr/bin/python": true, "/usr/bin/perl": true,
    "/usr/bin/nc": true, "/usr/bin/ncat": true, "/usr/bin/socat": true,
}

var sensitivePaths = []string{
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/.ssh/authorized_keys", "/etc/crontab",
}

// Handle is the single entry point the agent's main loop calls for
// every decoded event. It now handles the new kernel events.
func (d *Detector) Handle(ev Event) {
    switch ev.Type {
    case EvtExec:
        d.handleExec(ev)
    case EvtOpen:
        d.handleOpen(ev)
    case EvtConnect:
        d.handleConnect(ev)
    case EvtPtrace:
        d.handlePtrace(ev)
    case EvtMprotect: // NEW
        d.handleMprotect(ev)
    case EvtVmWritev: // NEW
        d.handleVmWritev(ev)
    }
}

func (d *Detector) handleExec(ev Event) {
    d.mu.Lock()
    d.procs[ev.Pid] = processState{
        execComm:  ev.Comm,
        execArgv0: ev.Argv0,
        execTime:  time.Now(),
    }
    d.mu.Unlock()

    // --- NEW: React to Kernel-Space LD_PRELOAD Detection ---
    if ev.AlertFlags&AlertLdPreloadFound != 0 {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "High",
            Technique:   "T1574.006", // Hijack Execution Flow: LD_PRELOAD
            Rule:        "ld-preload-injection",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("process %d exec'd %q with LD_PRELOAD set (kernel flagged)", ev.Pid, ev.Filename),
        })
    }

    // Rule: argv[0] doesn't match the invoked binary path.
    if ev.Argv0 != "" && !strings.HasSuffix(ev.Filename, trimLeadingDash(ev.Argv0)) &&
        !strings.Contains(ev.Argv0, baseName(ev.Filename)) {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "Medium",
            Technique:   "T1036.005",
            Rule:        "argv0-filename-mismatch",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("process %d exec'd %q with mismatched argv[0]=%q", ev.Pid, ev.Filename, ev.Argv0),
        })
    }

    // Rule: known LOLBin/shell exec'd from a webserver-family parent
    if shellBinaries[ev.Filename] && isWebServerComm(ev.Comm) {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "High",
            Technique:   "T1059.004",
            Rule:        "shell-from-webserver",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("shell %q spawned with parent comm %q (webserver-family)", ev.Filename, ev.Comm),
        })
    }
}

func (d *Detector) handleOpen(ev Event) {
    for _, p := range sensitivePaths {
        if ev.Filename == p {
            d.emit(Alert{
                Time:        time.Now(),
                Severity:    "Medium",
                Technique:   "T1552",
                Rule:        "sensitive-file-access",
                Pid:         ev.Pid,
                Ppid:        ev.Ppid,
                Comm:        ev.Comm,
                Description: fmt.Sprintf("process %q (pid %d) opened sensitive path %q", ev.Comm, ev.Pid, ev.Filename),
            })
            return
        }
    }
}

func (d *Detector) handleConnect(ev Event) {
    d.mu.Lock()
    st, hadExec := d.procs[ev.Pid]
    d.mu.Unlock()

    // --- UPGRADED: Trust Kernel Pre-Correlation or fall back to Go correlation ---
    // The kernel sets AlertReverseShellLikely if a shell connected outbound.
    // We also keep our Go logic for webserver-spawned shells that take longer.
    if (hadExec && shellBinaries[st.execComm]) || 
       (ev.AlertFlags&AlertReverseShellLikely != 0) || 
       (hadExec && time.Since(st.execTime) < 3*time.Second && isShellComm(ev.Comm)) {
       
        d.emit(Alert{
            Time:      time.Now(),
            Severity:  "Critical",
            Technique: "T1059",
            Rule:      "reverse-shell-pattern",
            Pid:       ev.Pid,
            Ppid:      ev.Ppid,
            Comm:      ev.Comm,
            Description: fmt.Sprintf(
                "pid %d (%s) exec'd a shell then connected to %s:%d — reverse-shell pattern (Kernel Flag: %t)",
                ev.Pid, ev.Comm, ev.DstAddr, ev.DstPort, ev.AlertFlags&AlertReverseShellLikely != 0),
        })
    }
}

func (d *Detector) handlePtrace(ev Event) {
    if !isDebuggerComm(ev.Comm) {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "High",
            Technique:   "T1055",
            Rule:        "unexpected-ptrace",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("process %q (pid %d) called ptrace() targeting pid %d", ev.Comm, ev.Pid, ev.TargetPid),
        })
    }
}

// --- NEW: W^X Bypass Detection ---
func (d *Detector) handleMprotect(ev Event) {
    if ev.AlertFlags&AlertWxBypass != 0 {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "Critical",
            Technique:   "T1055", // Process Injection (Memory modification)
            Rule:        "wx-memory-bypass",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("process %q (pid %d) requested W^X memory (Write/Execute) via mprotect()", ev.Comm, ev.Pid),
        })
    }
}

// --- NEW: Cross-Process Memory Injection ---
func (d *Detector) handleVmWritev(ev Event) {
    if ev.AlertFlags&AlertCrossProcessInject != 0 {
        d.emit(Alert{
            Time:        time.Now(),
            Severity:    "Critical",
            Technique:   "T1055.009", // Process Injection: Proc Memory
            Rule:        "cross-process-memory-write",
            Pid:         ev.Pid,
            Ppid:        ev.Ppid,
            Comm:        ev.Comm,
            Description: fmt.Sprintf("process %q (pid %d) wrote memory to a DIFFERENT pid %d via process_vm_writev()", ev.Comm, ev.Pid, ev.TargetPid),
        })
    }
}

func (d *Detector) emit(a Alert) {
    if d.onAlert != nil {
        d.onAlert(a)
    }
}

// --- small string helpers ---

func baseName(path string) string {
    i := strings.LastIndex(path, "/")
    if i < 0 {
        return path
    }
    return path[i+1:]
}

func trimLeadingDash(s string) string {
    return strings.TrimPrefix(s, "-")
}

func isWebServerComm(comm string) bool {
    switch comm {
    case "nginx", "apache2", "httpd", "php-fpm", "gunicorn", "uwsgi", "node", "java", "tomcat":
        return true
    }
    return false
}

func isShellComm(comm string) bool {
    switch comm {
    case "sh", "bash", "dash", "zsh", "python3", "python", "perl", "nc", "ncat", "socat":
        return true
    }
    return false
}

func isDebuggerComm(comm string) bool {
    switch comm {
    case "gdb", "strace", "ltrace", "perf", "bpftrace":
        return true
    }
    return false
}