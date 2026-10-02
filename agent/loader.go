package main

import (
    "bytes"
    _ "embed"
    "errors"
    "fmt"
    "log"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:embed monitor.bpf.o
var bpfObject []byte

type LoadedProbes struct {
    collection *ebpf.Collection
    links      []link.Link
    reader     *ringbuf.Reader
}

func LoadAndAttach() (*LoadedProbes, error) {
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("removing memlock rlimit: %w", err)
    }

    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
    if err != nil {
        return nil, fmt.Errorf("parsing embedded BPF object: %w", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        var ve *ebpf.VerifierError
        if errors.As(err, &ve) {
            return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
        }
        return nil, fmt.Errorf("loading BPF collection: %w", err)
    }

    lp := &LoadedProbes{collection: coll}

    attach := func(progName, kind, target string) error {
        prog := coll.Programs[progName]
        if prog == nil {
            return fmt.Errorf("program %q not found in compiled object", progName)
        }

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
        if err != nil {
            return fmt.Errorf("attaching %s to %s %s: %w", progName, kind, target, err)
        }
        lp.links = append(lp.links, l)
        return nil
    }

    // Tracepoints are stable syscall instrumentation and remain required.
    // Kernel network functions vary across distro/kernel versions, so the
    // network kprobes are optional: the agent keeps all available telemetry
    // rather than failing startup because one symbol is absent.
    hooks := []struct {
        prog, kind, target string
        required           bool
    }{
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

        // IPv4 + IPv6 TCP.
        {"trace_connect_v4", "kprobe", "tcp_v4_connect", false},
        {"trace_connect_v6", "kprobe", "tcp_v6_connect", false},

        // IPv4 + IPv6 UDP.
        {"trace_udp_sendmsg", "kprobe", "udp_sendmsg", false},
        {"trace_udpv6_sendmsg", "kprobe", "udpv6_sendmsg", false},

        // TCP inbound/listener visibility.
        {"trace_inet_csk_accept", "kretprobe", "inet_csk_accept", false},
        {"trace_listen_start", "kprobe", "inet_csk_listen_start", false},

        // Credential transition and other security telemetry.
        {"trace_commit_creds", "kprobe", "commit_creds", false},
    }

    for _, h := range hooks {
        if err := attach(h.prog, h.kind, h.target); err != nil {
            if h.required {
                lp.Close()
                return nil, err
            }
            log.Printf("WARNING: optional probe %s (%s:%s) not attached: %v", h.prog, h.kind, h.target, err)
            continue
        }
        log.Printf("attached %s -> %s:%s", h.prog, h.kind, h.target)
    }

    rd, err := ringbuf.NewReader(coll.Maps["events"])
    if err != nil {
        lp.Close()
        return nil, fmt.Errorf("opening ring buffer reader: %w", err)
    }
    lp.reader = rd

    return lp, nil
}

func (lp *LoadedProbes) Read() (Event, error) {
    record, err := lp.reader.Read()
    if err != nil {
        return Event{}, err
    }
    return parseEvent(record.RawSample)
}

func (lp *LoadedProbes) Close() {
    if lp.reader != nil {
        _ = lp.reader.Close()
    }
    for _, l := range lp.links {
        _ = l.Close()
    }
    if lp.collection != nil {
        lp.collection.Close()
    }
}
