package main

import (
    "bytes"
    _ "embed"
    "errors"
    "fmt"
    "log"
    "net"
    "os"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:embed monitor.bpf.o
var bpfObject []byte

//go:embed xdp.bpf.o
var xdpObject []byte

type LoadedProbes struct {
    collection *ebpf.Collection
    xdpCollection *ebpf.Collection
    links      []link.Link
    readers    []*ringbuf.Reader
    events     chan Event
    done       chan struct{}
    dropMap    *ebpf.Map
}

func loadCollection(object []byte) (*ebpf.Collection, error) {
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
    if err != nil {
        return nil, fmt.Errorf("parsing BPF object: %w", err)
    }
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        var ve *ebpf.VerifierError
        if errors.As(err, &ve) {
            return nil, fmt.Errorf("verifier rejected program:
%+v", ve)
        }
        return nil, fmt.Errorf("loading BPF collection: %w", err)
    }
    return coll, nil
}

func LoadAndAttach() (*LoadedProbes, error) {
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("removing memlock rlimit: %w", err)
    }

    coll, err := loadCollection(bpfObject)
    if err != nil { return nil, err }

    lp := &LoadedProbes{collection: coll, events: make(chan Event, 1024), done: make(chan struct{})}

    attach := func(progName, kind, target string) error {
        prog := coll.Programs[progName]
        if prog == nil { return fmt.Errorf("program %q not found", progName) }
        var l link.Link
        switch kind {
        case "tracepoint":
            category, name := splitTracepoint(target)
            l, err = link.Tracepoint(category, name, prog, nil)
        case "kprobe":
            l, err = link.Kprobe(target, prog, nil)
        case "kretprobe":
            l, err = link.Kretprobe(target, prog, nil)
        default:
            return fmt.Errorf("unknown hook kind %q", kind)
        }
        if err != nil { return fmt.Errorf("attaching %s to %s %s: %w", progName, kind, target, err) }
        lp.links = append(lp.links, l)
        return nil
    }

    hooks := []struct{ prog, kind, target string; required bool }{
        {"trace_execve", "tracepoint", "syscalls/sys_enter_execve", true},
        {"trace_openat", "tracepoint", "syscalls/sys_enter_openat", true},
        {"trace_ptrace", "tracepoint", "syscalls/sys_enter_ptrace", true},
        {"trace_mprotect", "tracepoint", "syscalls/sys_enter_mprotect", true},
        {"trace_process_vm_writev", "tracepoint", "syscalls/sys_enter_process_vm_writev", true},
        {"trace_init_module", "tracepoint", "syscalls/sys_enter_init_module", false},
        {"trace_finit_module", "tracepoint", "syscalls/sys_enter_finit_module", false},
        {"trace_bpf", "tracepoint", "syscalls/sys_enter_bpf", false},
        {"trace_memfd_create", "tracepoint", "syscalls/sys_enter_memfd_create", false},
        {"trace_socket", "tracepoint", "syscalls/sys_enter_socket", false},
        {"trace_unlinkat", "tracepoint", "syscalls/sys_enter_unlinkat", false},
        {"trace_setns", "tracepoint", "syscalls/sys_enter_setns", false},
        {"trace_connect_v4", "kprobe", "tcp_v4_connect", false},
        {"trace_ip_rcv", "kprobe", "ip_rcv", false},
        {"trace_ip6_rcv", "kprobe", "ip6_rcv", false},
        {"trace_ip_output", "kprobe", "ip_output", false},
        {"trace_ip6_finish_output2", "kprobe", "ip6_finish_output2", false},
        {"trace_connect_v6", "kprobe", "tcp_v6_connect", false},
        {"trace_udp_sendmsg", "kprobe", "udp_sendmsg", false},
        {"trace_udpv6_sendmsg", "kprobe", "udpv6_sendmsg", false},
        {"trace_inet_csk_accept", "kretprobe", "inet_csk_accept", false},
        {"trace_listen_start", "kprobe", "inet_csk_listen_start", false},
        {"trace_commit_creds", "kprobe", "commit_creds", false},
    }
    for _, h := range hooks {
        if err := attach(h.prog, h.kind, h.target); err != nil {
            if h.required { lp.Close(); return nil, err }
            log.Printf("WARNING: optional probe %s (%s:%s) not attached: %v", h.prog, h.kind, h.target, err)
        } else {
            log.Printf("attached %s -> %s:%s", h.prog, h.kind, h.target)
        }
    }

    traceReader, err := ringbuf.NewReader(coll.Maps["events"])
    if err != nil { lp.Close(); return nil, fmt.Errorf("opening ring buffer reader: %w", err) }
    lp.readers = append(lp.readers, traceReader)
    lp.dropMap = coll.Maps["ringbuf_drops"]

    // XDP is opt-in because attaching to an interface changes packet visibility
    // and requires an explicit operator choice.
    if ifname := os.Getenv("EDR_XDP_INTERFACE"); ifname != "" {
        iface, ierr := net.InterfaceByName(ifname)
        if ierr != nil { lp.Close(); return nil, fmt.Errorf("XDP interface %q: %w", ifname, ierr) }
        xcoll, xerr := loadCollection(xdpObject)
        if xerr != nil { lp.Close(); return nil, fmt.Errorf("loading XDP object: %w", xerr) }
        prog := xcoll.Programs["xdp_ingress"]
        if prog == nil { xcoll.Close(); lp.Close(); return nil, fmt.Errorf("XDP program xdp_ingress not found") }
        xl, xerr := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: link.XDPGenericMode})
        if xerr != nil {
            xcoll.Close()
            lp.Close()
            return nil, fmt.Errorf("attaching XDP to %s: %w", ifname, xerr)
        }
        xr, xerr := ringbuf.NewReader(xcoll.Maps["xdp_events"])
        if xerr != nil {
            _ = xl.Close(); xcoll.Close(); lp.Close()
            return nil, fmt.Errorf("opening XDP ring buffer: %w", xerr)
        }
        lp.xdpCollection = xcoll
        lp.links = append(lp.links, xl)
        lp.readers = append(lp.readers, xr)
        log.Printf("attached XDP ingress telemetry -> %s (generic mode)", ifname)
    } else {
        log.Printf("XDP telemetry disabled; set EDR_XDP_INTERFACE to enable it")
    }

    for _, rd := range lp.readers {
        go lp.readLoop(rd)
    }
    return lp, nil
}

func (lp *LoadedProbes) readLoop(rd *ringbuf.Reader) {
    for {
        record, err := rd.Read()
        if err != nil { return }
        ev, err := parseEvent(record.RawSample)
        if err != nil { continue }
        select {
        case lp.events <- ev:
        case <-lp.done:
            return
        }
    }
}

func (lp *LoadedProbes) Read() (Event, error) {
    ev, ok := <-lp.events
    if !ok { return Event{}, ringbuf.ErrClosed }
    return ev, nil
}

func (lp *LoadedProbes) RingbufDrops() uint64 {
    if lp.dropMap == nil { return 0 }
    var key uint32
    var drops uint64
    if err := lp.dropMap.Lookup(&key, &drops); err != nil { return 0 }
    return drops
}

func (lp *LoadedProbes) Close() {
    select { case <-lp.done: default: close(lp.done) }
    for _, rd := range lp.readers { _ = rd.Close() }
    for _, l := range lp.links { _ = l.Close() }
    if lp.xdpCollection != nil { lp.xdpCollection.Close() }
    if lp.collection != nil { lp.collection.Close() }
    select { case <-lp.done: default: close(lp.done) }
}
