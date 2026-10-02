package main

import (
    "fmt"
    "strings"
    "sync"
    "time"
)

type Alert struct {
    Time        time.Time `json:"time"`
    Severity    string `json:"severity"`
    Technique   string `json:"mitre_technique"`
    Rule        string `json:"rule"`
    Pid         uint32 `json:"pid"`
    Ppid        uint32 `json:"ppid"`
    Comm        string `json:"comm"`
    Description string `json:"description"`

    Protocol  string `json:"protocol,omitempty"`
    Family    string `json:"family,omitempty"`
    Direction string `json:"direction,omitempty"`
    SrcAddr   string `json:"src_addr,omitempty"`
    SrcPort   uint16 `json:"src_port,omitempty"`
    DstAddr   string `json:"dst_addr,omitempty"`
    DstPort   uint16 `json:"dst_port,omitempty"`
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
    config Config
}

func NewDetector(onAlert func(Alert), config Config) *Detector {
    d := &Detector{procs: make(map[uint32]processState), ttl: 30 * time.Second, onAlert: onAlert, config: config}
    go d.reaper()
    return d
}

func (d *Detector) reaper() {
    t := time.NewTicker(10 * time.Second)
    for range t.C {
        d.mu.Lock()
        now := time.Now()
        for pid, st := range d.procs {
            if now.Sub(st.execTime) > d.ttl { delete(d.procs, pid) }
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

func (d *Detector) Handle(ev Event) {
    if d.config.AllowedComms[ev.Comm] || (ev.Filename != "" && d.config.AllowedExecutables[ev.Filename]) {
        return
    }
    switch ev.Type {
    case EvtExec:
        d.handleExec(ev)
    case EvtOpen:
        d.handleOpen(ev)
    case EvtConnect:
        d.handleConnect(ev)
    case EvtAccept:
        d.handleAccept(ev)
    case EvtListen:
        d.handleListen(ev)
    case EvtPtrace:
        d.handlePtrace(ev)
    case EvtMprotect:
        d.handleMprotect(ev)
    case EvtVmWritev:
        d.handleVmWritev(ev)
    case EvtModuleLoad, EvtBPF, EvtPrivEsc, EvtMemFD, EvtSocketCreate, EvtUnlink, EvtSetNS:
        d.handleKernelSecurityEvent(ev)
    }
}

func (d *Detector) handleExec(ev Event) {
    d.mu.Lock()
    d.procs[ev.Tgid] = processState{execComm: ev.Comm, execArgv0: ev.Argv0, execTime: time.Now()}
    d.mu.Unlock()

    if ev.AlertFlags&AlertLdPreloadFound != 0 {
        d.emit(Alert{Time: time.Now(), Severity: "High", Technique: "T1574.006",
            Rule: "ld-preload-injection", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
            Description: fmt.Sprintf("process %d exec'd %q with LD_PRELOAD set (kernel flagged)", ev.Pid, ev.Filename)})
    }
    if ev.AlertFlags&AlertFilelessExec != 0 {
        d.emit(Alert{Time: time.Now(), Severity: "Critical", Technique: "T1620",
            Rule: "fileless-execution", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
            Description: fmt.Sprintf("process %d (%s) executed a fileless target %q", ev.Pid, ev.Comm, ev.Filename)})
    }
    if ev.Argv0 != "" && !strings.HasSuffix(ev.Filename, trimLeadingDash(ev.Argv0)) &&
        !strings.Contains(ev.Argv0, baseName(ev.Filename)) {
        d.emit(Alert{Time: time.Now(), Severity: "Medium", Technique: "T1036.005",
            Rule: "argv0-filename-mismatch", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
            Description: fmt.Sprintf("process %d exec'd %q with mismatched argv[0]=%q", ev.Pid, ev.Filename, ev.Argv0)})
    }
    if shellBinaries[ev.Filename] && isWebServerComm(ev.Comm) {
        d.emit(Alert{Time: time.Now(), Severity: "High", Technique: "T1059.004",
            Rule: "shell-from-webserver", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
            Description: fmt.Sprintf("shell %q spawned with parent comm %q (webserver-family)", ev.Filename, ev.Comm)})
    }
}

func (d *Detector) handleOpen(ev Event) {
    if ev.AlertFlags&AlertPersistenceWrite != 0 {
        technique := persistenceTechnique(ev.Filename)
        d.emit(Alert{Time: time.Now(), Severity: "High", Technique: technique,
            Rule: "persistence-write", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
            Description: fmt.Sprintf("process %q opened persistence-sensitive path %q for writing", ev.Comm, ev.Filename)})
    }
    for _, p := range sensitivePaths {
        if ev.Filename == p {
            d.emit(Alert{Time: time.Now(), Severity: "Medium", Technique: "T1552",
                Rule: "sensitive-file-access", Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
                Description: fmt.Sprintf("process %q (pid %d) opened sensitive path %q", ev.Comm, ev.Pid, ev.Filename)})
            return
        }
    }
}

func (d *Detector) handleConnect(ev Event) {
    d.mu.Lock()
    st, hadExec := d.procs[ev.Tgid]
    d.mu.Unlock()

    kernelFlagged := ev.AlertFlags&AlertReverseShellLikely != 0
    shellConnected := hadExec && shellBinaries[st.execComm]
    recentShell := hadExec && time.Since(st.execTime) < 3*time.Second && isShellComm(ev.Comm)
    if !shellConnected && !kernelFlagged && !recentShell { return }

    d.emit(Alert{
        Time: time.Now(), Severity: "Critical", Technique: "T1059", Rule: "reverse-shell-pattern",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Protocol: ev.ProtocolName(), Family: ev.FamilyName(), Direction: ev.DirectionName(),
        SrcAddr: ipString(ev.SrcAddr, ev.SrcAddr6), SrcPort: ev.SrcPort,
        DstAddr: ipString(ev.DstAddr, ev.DstAddr6), DstPort: ev.DstPort,
        Description: fmt.Sprintf("pid %d (%s) generated %s %s traffic to %s:%d — reverse-shell pattern (kernel flag=%t)",
            ev.Pid, ev.Comm, ev.FamilyName(), ev.ProtocolName(),
            ipString(ev.DstAddr, ev.DstAddr6), ev.DstPort, kernelFlagged),
    })
}

func (d *Detector) handleAccept(ev Event) {
    if ev.AlertFlags&AlertBindShellLikely == 0 { return }
    d.emit(Alert{
        Time: time.Now(), Severity: "Critical", Technique: "T1059", Rule: "bind-shell-pattern",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Protocol: ev.ProtocolName(), Family: ev.FamilyName(), Direction: ev.DirectionName(),
        SrcAddr: ipString(ev.SrcAddr, ev.SrcAddr6), SrcPort: ev.SrcPort,
        DstAddr: ipString(ev.DstAddr, ev.DstAddr6), DstPort: ev.DstPort,
        Description: fmt.Sprintf("shell process accepted an inbound %s connection on port %d", ev.ProtocolName(), ev.SrcPort),
    })
}

func (d *Detector) handleListen(ev Event) {
    if ev.AlertFlags&AlertUnexpectedListener == 0 { return }
    d.emit(Alert{
        Time: time.Now(), Severity: "High", Technique: "T1571", Rule: "unexpected-listener",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Protocol: ev.ProtocolName(), Family: ev.FamilyName(), Direction: ev.DirectionName(),
        SrcPort: ev.SrcPort,
        Description: fmt.Sprintf("shell/interpreter process %q started listening on %s port %d", ev.Comm, ev.ProtocolName(), ev.SrcPort),
    })
}

func (d *Detector) handlePtrace(ev Event) {
    if isDebuggerComm(ev.Comm) { return }
    d.emit(Alert{Time: time.Now(), Severity: "High", Technique: "T1055", Rule: "unexpected-ptrace",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Description: fmt.Sprintf("process %q (pid %d) called ptrace() targeting pid %d", ev.Comm, ev.Pid, ev.TargetPid)})
}

func (d *Detector) handleMprotect(ev Event) {
    if ev.AlertFlags&AlertWxBypass == 0 { return }
    d.emit(Alert{Time: time.Now(), Severity: "Critical", Technique: "T1055", Rule: "wx-memory-bypass",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Description: fmt.Sprintf("process %q (pid %d) requested W^X memory via mprotect()", ev.Comm, ev.Pid)})
}

func (d *Detector) handleVmWritev(ev Event) {
    if ev.AlertFlags&AlertCrossProcessInject == 0 { return }
    d.emit(Alert{Time: time.Now(), Severity: "Critical", Technique: "T1055.009", Rule: "cross-process-memory-write",
        Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        Description: fmt.Sprintf("process %q (pid %d) wrote memory to pid %d via process_vm_writev()", ev.Comm, ev.Pid, ev.TargetPid)})
}

func (d *Detector) handleKernelSecurityEvent(ev Event) {
    var a *Alert
    switch {
    case ev.AlertFlags&AlertKernelModuleLoad != 0:
        a = &Alert{Severity: "Critical", Technique: "T1547.006", Rule: "kernel-module-load",
            Description: fmt.Sprintf("process %q loaded a kernel module", ev.Comm)}
    case ev.AlertFlags&AlertUnauthorizedBPF != 0:
        a = &Alert{Severity: "High", Technique: "", Rule: "bpf-program-load",
            Description: fmt.Sprintf("process %q attempted to load an eBPF program", ev.Comm)}
    case ev.AlertFlags&AlertPrivEscToRoot != 0:
        a = &Alert{Severity: "Critical", Technique: "T1548", Rule: "privilege-escalation-to-root",
            Description: fmt.Sprintf("credential transition changed uid from %d to root for process %q", ev.OldUID, ev.Comm)}
    case ev.AlertFlags&AlertRawSocket != 0:
        a = &Alert{Severity: "High", Technique: "", Rule: "raw-or-packet-socket",
            Description: fmt.Sprintf("process %q created a raw/packet socket (family=%d type=%d)", ev.Comm, ev.SockFamily, ev.SockType)}
    case ev.AlertFlags&AlertSelfDelete != 0:
        a = &Alert{Severity: "High", Technique: "T1070.004", Rule: "self-delete",
            Description: fmt.Sprintf("process %q unlinked its own executable path %q", ev.Comm, ev.Filename)}
    case ev.AlertFlags&AlertNamespaceManipulation != 0:
        a = &Alert{Severity: "High", Technique: "T1611", Rule: "namespace-manipulation",
            Description: fmt.Sprintf("process %q invoked setns()", ev.Comm)}
    }
    if a == nil { return }
    a.Time, a.Pid, a.Ppid, a.Comm = time.Now(), ev.Pid, ev.Ppid, ev.Comm
    d.emit(*a)
}

func (d *Detector) emit(a Alert) {
    if d.config.DisabledRules[a.Rule] {
        return
    }
    if d.config.AllowedComms[a.Comm] {
        return
    }
    if d.onAlert != nil { d.onAlert(a) }
}

func ipString(v4, v6 interface{ String() string }) string {
    if v6 != nil && v6.String() != "<nil>" && v6.String() != "" { return v6.String() }
    if v4 != nil && v4.String() != "<nil>" && v4.String() != "" { return v4.String() }
    return ""
}

func baseName(path string) string {
    i := strings.LastIndex(path, "/")
    if i < 0 { return path }
    return path[i+1:]
}

func trimLeadingDash(s string) string { return strings.TrimPrefix(s, "-") }

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


func persistenceTechnique(path string) string {
    switch {
    case strings.Contains(path, ".ssh/authorized_keys"):
        return "T1098.004"
    case strings.HasPrefix(path, "/etc/cron"):
        return "T1053.003"
    case strings.HasPrefix(path, "/etc/systemd/system/"):
        return "T1543.002"
    case strings.HasPrefix(path, "/etc/ld.so.preload"):
        return "T1574.006"
    default:
        return "T1547"
    }
}
