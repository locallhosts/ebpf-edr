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
// The compiled BPF object is embedded directly into the agent binary at
// build time. This means the deployed agent is a single static binary —
// no clang, no libbpf headers, no source tree needs to exist on the
// target machine.
//
//go:embed monitor.bpf.o
var bpfObject []byte

// LoadedProbes holds every attached link and the ring buffer reader so
// the caller can clean up deterministically on shutdown.
type LoadedProbes struct {
    collection *ebpf.Collection
    links      []link.Link
    reader     *ringbuf.Reader
}

// LoadAndAttach loads the embedded BPF object, verifies it against the
// running kernel, and attaches every program to its target hook.
func LoadAndAttach() (*LoadedProbes, error) {
    // eBPF requires elevated resource limits for locked memory on
    // kernels without cgroup-based BPF memory accounting (< 5.11).
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
            // %+v on a VerifierError prints the full instruction-level
            // verifier log, which is exactly what you want when a
            // kernel rejects the program.
            return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
        }
        return nil, fmt.Errorf("loading BPF collection: %w", err)
    }

    lp := &LoadedProbes{collection: coll}

    // Helper to attach programs
    attach := func(progName, kind, target string) error {
        prog := coll.Programs[progName]
        if prog == nil {
            return fmt.Errorf("program %q not found in compiled object", progName)
        }
        var l link.Link
        var err error
        switch kind {
        case "tracepoint":
            category, name := splitTracepoint(target) // splitTracepoint is in utils.go
            l, err = link.Tracepoint(category, name, prog, nil)
        case "kprobe":
            l, err = link.Kprobe(target, prog, nil)
        default:
            return fmt.Errorf("unknown hook kind %q", kind)
        }
        if err != nil {
            return fmt.Errorf("attaching %s to %s %s: %w", progName, kind, target, err)
        }
        lp.links = append(lp.links, l)
        return nil
    }

    // Define all kernel hooks
    hooks := []struct {
        prog, kind, target string
        required           bool
    }{
        {"trace_execve", "tracepoint", "syscalls/sys_enter_execve", true},
        {"trace_openat", "tracepoint", "syscalls/sys_enter_openat", true},
        // kprobes need a deeper privilege level than tracepoints
        {"trace_connect", "kprobe", "tcp_v4_connect", false},
        {"trace_ptrace", "tracepoint", "syscalls/sys_enter_ptrace", true},
        // NEW: Memory protection and cross-process injection detection
        {"trace_mprotect", "tracepoint", "syscalls/sys_enter_mprotect", true},
        {"trace_process_vm_writev", "tracepoint", "syscalls/sys_enter_process_vm_writev", true},
    }

    for _, h := range hooks {
        if err := attach(h.prog, h.kind, h.target); err != nil {
            if h.required {
                lp.Close()
                return nil, err
            }
            log.Printf("WARNING: optional probe %s (%s:%s) not attached: %v", h.prog, h.kind, h.target, err)
            log.Printf("  -> this host/container restricts kprobes; network-connect detection will be unavailable until run with fuller privileges")
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

// Read blocks until the next event is available (or the reader is
// closed during shutdown, in which case it returns ringbuf.ErrClosed).
func (lp *LoadedProbes) Read() (Event, error) {
    record, err := lp.reader.Read()
    if err != nil {
        return Event{}, err
    }
    return parseEvent(record.RawSample)
}

// Close cleanly detaches all BPF links and closes the collection.
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