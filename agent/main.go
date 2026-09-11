// Command edr-agent is the userspace half of the eBPF kernel threat
// detection agent. It loads the compiled eBPF programs (embedded at
// build time from bpf/monitor.bpf.o), attaches them to kernel
// tracepoints/kprobes, streams events out of the shared ring buffer,
// runs them through the detection engine, and exposes results via
// Prometheus metrics and a small JSON API for the dashboard.
//
// Requires: Linux kernel 5.8+ (ring buffer support), CAP_BPF (or root),
// and a kernel built with BTF (CONFIG_DEBUG_INFO_BTF=y — true on every
// mainstream distro kernel since ~2020).
//
// Usage:
//
//	sudo go run . -addr :9090
package main

import (
    "errors"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/cilium/ebpf/ringbuf"
)

// ANSI color codes for terminal output
const (
    colorReset  = "\033[0m"
    colorRed    = "\033[31m"
    colorYellow = "\033[33m"
    colorGreen  = "\033[32m"
)

func main() {
    addr := flag.String("addr", ":9090", "address for the metrics/API HTTP server")
    flag.Parse()

    if os.Geteuid() != 0 {
        log.Fatal("edr-agent must run as root (or with CAP_BPF + CAP_PERFMON) to load eBPF programs")
    }

    log.Println("loading eBPF programs and attaching to kernel hooks...")
    probes, err := LoadAndAttach()
    if err != nil {
        log.Fatalf("failed to load/attach eBPF programs: %v", err)
    }
    defer probes.Close()
    
    fmt.Println("------------------------------------------------------------------")
    log.Println("Sentinel-eBPF Agent is running. Monitoring live syscalls...")
    fmt.Println("------------------------------------------------------------------")

    store := NewAlertStore(500)
    
    // Initialize the detection engine with a callback that handles triggered alerts
    detector := NewDetector(func(a Alert) {
        store.Add(a)
        
        // Color code based on severity
        var color string
        switch a.Severity {
        case "Critical", "High":
            color = colorRed
        case "Medium":
            color = colorYellow
        default:
            color = colorGreen
        }

        log.Printf("%s[ALERT][%s] %s (rule=%s technique=%s pid=%d comm=%s)%s",
            color, a.Severity, a.Description, a.Rule, a.Technique, a.Pid, a.Comm, colorReset)
    })

    // Start the HTTP server in a background goroutine for the React dashboard & Prometheus
    go ServeHTTP(*addr, store)

    // Graceful shutdown on SIGINT/SIGTERM: detach probes cleanly rather
    // than leaving orphaned BPF links pinned in the kernel.
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-sigCh
        fmt.Println("\n------------------------------------------------------------------")
        log.Println("shutting down, detaching probes...")
        probes.Close()
        os.Exit(0)
    }()

    // Main event loop: Read from kernel ring buffer -> Update Metrics -> Run Detection Engine
    for {
        ev, err := probes.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                return
            }
            log.Printf("ring buffer read error: %v", err)
            continue
        }

        // Update Prometheus metrics
        eventsTotal.WithLabelValues(ev.TypeName()).Inc()
        latency := time.Duration(uint64(time.Now().UnixNano()) - ev.TimestampNs)
        if latency > 0 {
            eventProcessLatency.Observe(latency.Seconds())
        }

        // Pass the event to the detection engine
        detector.Handle(ev)
    }
}