# eBPF EDR — Linux Kernel Security Telemetry & Detection

[![eBPF EDR Build](https://github.com/locallhosts/ebpf-edr/actions/workflows/build.yml/badge.svg)](https://github.com/locallhosts/ebpf-edr/actions/workflows/build.yml)
[![Language](https://img.shields.io/badge/eBPF-C-blue)](https://ebpf.io/)
[![Userspace](https://img.shields.io/badge/userspace-Go-00ADD8)](https://go.dev/)
[![Dashboard](https://img.shields.io/badge/dashboard-React%20%2F%20TypeScript-61DAFB)](https://react.dev/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624)](https://www.linux.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Linux security-engineering project that combines **eBPF kernel instrumentation**, a **Go telemetry and detection agent**, and a **React/TypeScript SOC dashboard**.

The system collects selected security and network signals close to the Linux kernel, transports structured events through BPF ring buffers, normalizes and correlates them in userspace, applies behavioral detections, and exposes alerts, network telemetry, health, and Prometheus metrics.

> **Status:** Research / Security Engineering Project  
> **Platform:** Linux  
> **Stack:** eBPF/C · Go · React/TypeScript  
> **Focus:** Kernel telemetry · Detection engineering · Network visibility · Security operations

![Live Demo - Terminal Alert](docs/assets/live-demo.gif)

<p align="center">
  <img src="docs/assets/live-demo_dashbaord.gif" alt="Live SOC Dashboard" width="48%">
  <img src="docs/assets/live-demo_web.gif" alt="Live Web Dashboard" width="48%">
</p>

---

## Why this project?

Traditional endpoint telemetry often observes activity at the application or userspace layer. eBPF provides another observation point inside the Linux kernel without requiring a custom kernel module.

This project explores the complete security telemetry path:

```
Linux Kernel
    │
    ├── Tracepoints / Kprobes / Kretprobes
    │
    └── Optional XDP ingress telemetry
            │
            ▼
       BPF Ring Buffer
            │
            ▼
        Go Agent
            │
     ┌──────┼──────────┐
     ▼      ▼          ▼
 Normalize  Correlate  Policy
     │      │          │
     └──────┼──────────┘
            ▼
       Detection Engine
            │
     ┌──────┼─────────────┐
     ▼      ▼             ▼
   REST   Prometheus    Webhooks
     │
     ▼
 React / TypeScript Dashboard
```

The goal is not to claim complete EDR coverage. The goal is to demonstrate a practical, testable kernel-to-detection security pipeline with explicit coverage boundaries.

---

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Kernel Telemetry](#kernel-telemetry)
- [Network Visibility](#network-visibility)
- [Event ABI](#event-abi)
- [Detection Engineering](#detection-engineering)
- [Operational Controls](#operational-controls)
- [SOC Dashboard](#soc-dashboard)
- [Observability](#observability)
- [Validation & Performance](#validation--performance)
- [Build & Run](#build--run)
- [CI](#ci)
- [Security Model & Limitations](#security-model--limitations)
- [Repository Structure](#repository-structure)
- [Engineering Workflow](#engineering-workflow)
- [Project Status](#project-status)

---

# Capabilities

### Endpoint telemetry

- Process execution via `execve`
- Sensitive file access via `openat`
- `ptrace()`
- `mprotect()` and W^X-related memory signals
- Cross-process memory writes via `process_vm_writev()`
- `memfd_create()`
- Namespace manipulation
- Process self-deletion
- Privilege-transition signals
- Kernel module loading
- eBPF program loading
- Raw/packet socket creation

### Network telemetry

- IPv4 and IPv6 TCP connections
- IPv4 and IPv6 UDP activity
- TCP accept/listener activity
- Socket creation context
- Generic IPv4/IPv6 packet metadata
- TCP/UDP/SCTP port extraction
- IP protocol identification
- Direction and packet length
- Optional Ethernet/L2 ingress telemetry through XDP
- One-tag VLAN parsing
- Bounded IPv6 extension-header traversal
- Metadata-only network observation; payloads are not captured

### Detection and operations

- Stateful process/network correlation
- Reverse-shell and bind-shell indicators
- Process-injection indicators
- Fileless-execution indicators
- Persistence indicators
- Namespace and raw-socket indicators
- Configurable disabled rules
- Communication and executable allow-lists
- Network metadata deduplication
- Container/cgroup context where available
- Prometheus metrics
- SIEM/SOAR webhook delivery
- REST API
- React/TypeScript dashboard

---

# Architecture

The project deliberately separates collection, transport, normalization, correlation, detection, and presentation.

| Layer | Responsibility |
|---|---|
| eBPF/C | Kernel instrumentation and event generation |
| BPF ring buffer | Structured kernel → userspace transport |
| Go loader | Object loading, probe attachment, event readers |
| Event decoder | C ABI → Go event model |
| Correlation | Short-lived process/network behavioral state |
| Detection | Security rules and contextual alerts |
| Policy | Rule suppression and deployment-specific allow-lists |
| API | Alerts, network telemetry, health, metrics |
| Dashboard | SOC-oriented visualization |

### Kernel collection

`bpf/monitor.bpf.c` contains endpoint and network instrumentation.

`bpf/xdp.bpf.c` provides optional generic-mode XDP ingress telemetry. XDP is disabled unless `EDR_XDP_INTERFACE` is explicitly configured.

### Go agent

`agent/` loads the embedded objects, attaches hooks, reads ring buffers, decodes events, maintains bounded state, evaluates detections, and exposes APIs/metrics.

### Dashboard

`dashboard/` contains the React/TypeScript security interface.

![eBPF EDR Architecture](docs/assets/architecture.png)

---

# Kernel Telemetry

The kernel layer uses:

- eBPF
- BTF-derived kernel types
- CO-RE-compatible reads
- Tracepoints
- Kprobes
- Kretprobes
- BPF maps
- BPF ring buffers
- Optional XDP

## Required hooks

The loader currently treats these core syscall tracepoints as required:

- `sys_enter_execve`
- `sys_enter_openat`
- `sys_enter_ptrace`
- `sys_enter_mprotect`
- `sys_enter_process_vm_writev`

Failure to attach a required hook prevents normal startup.

## Optional hooks

Security and compatibility-sensitive hooks are attempted when available:

- `sys_enter_init_module`
- `sys_enter_finit_module`
- `sys_enter_bpf`
- `sys_enter_memfd_create`
- `sys_enter_socket`
- `sys_enter_unlinkat`
- `sys_enter_setns`
- `tcp_v4_connect`
- `tcp_v6_connect`
- `udp_sendmsg`
- `udpv6_sendmsg`
- `inet_csk_accept`
- `inet_csk_listen_start`
- `ip_rcv`
- `ip6_rcv`
- `ip_output`
- `ip6_finish_output2`
- `commit_creds`

Optional probes fail independently and are logged as warnings rather than making the entire agent unusable.

---

# Network Visibility

Network telemetry intentionally combines **process-aware socket events** with **generic packet metadata**.

## Socket-aware telemetry

The agent observes:

```
TCP v4/v6 connect
UDP v4/v6 send
TCP accept
TCP listen
socket()
```

Socket events preserve process context when that context exists.

## Generic packet telemetry

The packet path observes IPv4/IPv6 metadata and records:

- Address family
- IP protocol number
- Source/destination address
- Source/destination port when applicable
- Direction
- Packet length
- Process context when available

Supported protocol identification includes TCP, UDP, ICMP, ICMPv6, SCTP, and arbitrary IP protocol numbers.

No packet payload is captured.

## XDP / Layer-2 telemetry

Set:

```bash
export EDR_XDP_INTERFACE=eth0
sudo ./bin/edr-agent
```

The XDP sensor:

- Parses Ethernet frames
- Handles one VLAN tag
- Identifies IPv4/IPv6
- Traverses bounded IPv6 extension headers
- Extracts TCP/UDP/SCTP ports
- Emits metadata into a dedicated BPF ring buffer
- Returns `XDP_PASS`

XDP is therefore a **visibility sensor**, not a firewall.

Because XDP executes at ingress before process context is available, XDP events use PID/TGID `0`.

## IPv6 extension headers

Both packet paths implement bounded traversal for:

- Hop-by-Hop Options
- Routing
- Fragment
- Destination Options
- Authentication Header

Traversal is deliberately bounded to keep parsing verifier-safe and prevent unbounded header walks.

## Coverage boundary

The generic kprobe packet path is primarily IPv4/IPv6 Layer-3 telemetry. Optional XDP adds Ethernet/L2 ingress visibility.

This does not constitute universal Ethernet visibility. ARP, LLDP, arbitrary non-IP Ethernet protocols, multiple VLAN/QinQ stacks, and other L2-specific traffic are outside the current scope.

Socket-level and packet-level hooks can observe related activity, so userspace applies bounded metadata deduplication rather than treating every observation as a unique security event.

---

# Event ABI

The eBPF and Go layers communicate through a fixed event structure.

The ABI carries fields including:

- Timestamp
- PID / PPID / TGID
- Process name
- Event type
- File/path context
- IPv4/IPv6 addresses
- Source/destination ports
- Target PID
- Address family
- Protocol
- Direction
- Credential context
- Socket fields
- Packet length

![eBPF EDR Event ABI](docs/assets/eventabi.png)

The event ABI is a compatibility boundary: changing the C structure requires coordinated userspace updates.

---

# Detection Engineering

Detection logic lives primarily in `agent/detect.go`.

The design separates **observation** from **interpretation**:

```
Kernel signal
    ↓
Structured event
    ↓
Process / network context
    ↓
Detection rule
    ↓
Alert
```

Example behavioral correlation:

```
Process execution
      ↓
Shell/interpreter
      ↓
Recent execution state
      ↓
Outbound network connection
      ↓
REVERSE_SHELL_LIKELY
```

Another:

```
Process A
   ↓
process_vm_writev()
   ↓
Process B
   ↓
CROSS_PROCESS_INJECT
```

### ATT&CK-aligned mappings

Current mappings include, where the observed behavior has a sufficiently specific ATT&CK relationship:

| Behavior | Mapping |
|---|---|
| SSH `authorized_keys` modification | T1098.004 |
| Cron persistence | T1053.003 |
| systemd service persistence | T1543.002 |
| Dynamic linker preload modification | T1574.006 |
| Kernel module loading | T1547.006 |
| Other persistence-sensitive paths | Context-dependent |

The project deliberately avoids assigning a technique when an observed event is too broad to justify a specific ATT&CK mapping.

### Detection is not a verdict

Security-sensitive operations can be legitimate.

Examples include:

- JIT runtimes using W^X-related memory transitions
- Debuggers using `ptrace()`
- Security tools using raw sockets
- Administrators loading kernel modules
- Container runtimes manipulating namespaces
- Applications using `memfd_create()`

Operational deployments should therefore add process identity, executable path, parent process, user, container identity, historical context, allow-lists, and host role.

![Detection Coverage](docs/assets/detection_coverage.png)

---

# Operational Controls

Detection policy is kept in userspace so telemetry collection remains stable while deployment-specific policy can change.

Supported controls include:

```text
EDR_DISABLED_RULES
EDR_ALLOW_COMMS
EDR_ALLOW_EXECUTABLES
```

Network telemetry is bounded and applies short-window metadata deduplication.

Container/cgroup context is best-effort and depends on the available Linux environment.

The agent can also asynchronously deliver security events to a generic SIEM/SOAR webhook with:

- Bounded delivery queue
- Bearer-token authentication
- Delivery/failure/drop metrics
- Non-blocking alert processing

---

# SOC Dashboard

The dashboard is implemented in React/TypeScript and consumes the Go API.

Current views include:

- Security alerts
- Severity
- Detection/rule metadata
- ATT&CK metadata
- Process context
- Network telemetry
- Timestamps

```
Kernel → eBPF → Go Agent → REST API → React Dashboard
```

![Live SOC Dashboard](docs/assets/live-demo_dashbaord.gif)

![SOC Dashboard](docs/assets/Capture-Web.PNG)

![Critical Alerts](docs/assets/dashboard-critical.png)

---

# Observability

Prometheus metrics expose operational behavior, including:

- Webhook deliveries
- Webhook failures
- Webhook queue drops
- Network event deduplication
- Kernel-side ring-buffer reservation losses

The ring-buffer loss counter is maintained in BPF when `bpf_ringbuf_reserve()` fails and surfaced through:

```text
edr_ringbuf_lost_total
```

This distinguishes actual kernel-side ring-buffer reservation loss from a userspace-only approximation.

Useful endpoints:

| Endpoint | Purpose |
|---|---|
| `/healthz` | Agent health |
| `/metrics` | Prometheus metrics |
| `/api/alerts` | Security alerts |
| `/api/network` | Bounded network telemetry |

---

# Validation & Performance

Validation is treated as part of the implementation rather than an afterthought.

Run:

```bash
sudo make test-validation
make test-perf
```

The validation workflow covers:

1. Go static analysis
2. Unit tests
3. Race-detector execution
4. Concurrency/stress tests
5. Userspace benchmarks
6. eBPF compilation
7. XDP compilation
8. Source-level coverage assertions
9. Kernel verifier/load validation when executed with root and `bpftool`

### Verifier validation

```bash
sudo make test-load
```

The test loads both the monitor and XDP objects through `bpftool` and removes the temporary pinned programs afterward.

### Ring-buffer loss validation

The kernel maintains a real reservation-failure counter. Controlled overload testing can then be performed in a privileged Linux lab while observing:

```text
edr_ringbuf_lost_total
```

The metric makes loss observable rather than silently discarding it.

---

# Build & Run

## Requirements

- Linux
- Kernel BTF support
- Clang / LLVM
- libbpf
- libelf
- bpftool
- Go 1.22+
- Node.js/npm for dashboard builds
- Sufficient privileges/capabilities for eBPF loading

Check BTF:

```bash
ls -l /sys/kernel/btf/vmlinux
```

## Ubuntu dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  clang \
  llvm \
  libbpf-dev \
  libelf-dev \
  linux-tools-common \
  linux-tools-generic
```

## Clone

```bash
git clone https://github.com/locallhosts/ebpf-edr.git
cd ebpf-edr
```

## Generate kernel types

```bash
make vmlinux
```

This generates `bpf/vmlinux.h` from:

```text
/sys/kernel/btf/vmlinux
```

Regenerate it when targeting a substantially different kernel.

## Build

```bash
make
```

This builds:

- eBPF monitor object
- XDP object
- Go agent

The resulting binary is:

```text
bin/edr-agent
```

## Run

```bash
sudo ./bin/edr-agent -addr :9090
```

Or:

```bash
make run
```

## Dashboard

```bash
make dashboard
```

Or:

```bash
cd dashboard
npm install
npm run build
```

---

# CI

GitHub Actions is defined in:

```text
.github/workflows/build.yml
```

The Linux CI pipeline:

```
Checkout
   ↓
Go toolchain
   ↓
Linux eBPF dependencies
   ↓
bpftool discovery
   ↓
Runner kernel BTF
   ↓
Generate vmlinux.h
   ↓
Compile eBPF + XDP
   ↓
Build Go agent
   ↓
Unit tests
   ↓
Security validation / benchmarks
```

The workflow accounts for Ubuntu runner differences when locating `bpftool` and validates the project against an actual Linux kernel/BTF environment.

---

# Security Model & Limitations

## Kernel trust

A sufficiently privileged kernel attacker can interfere with the observation layer. eBPF telemetry should not be treated as an independent trusted boundary after kernel compromise.

## Coverage

This is selected behavioral telemetry, not complete Linux visibility. Absence of an event does not prove absence of malicious activity.

## Kernel compatibility

BTF and CO-RE improve portability, but deployment still depends on:

- Kernel version
- BTF availability
- Helper support
- Verifier behavior
- Probe symbols
- Distribution configuration

Optional probes may legitimately be unavailable.

## Event pressure

High event rates can pressure both the BPF ring buffer and userspace processing path. The kernel-side drop counter makes reservation loss observable, but no telemetry system can guarantee zero loss under arbitrary overload.

## XDP context

XDP runs before process context is available. XDP events therefore use PID/TGID `0`.

## Network scope

Payload capture is intentionally excluded. The project focuses on metadata and endpoint context rather than full packet inspection.

## Detection semantics

Alerts are behavioral signals, not proof of compromise. Production deployments require environment-specific tuning and independent validation.

---

# Repository Structure

```text
ebpf-edr/
├── agent/
│   ├── detect.go
│   ├── loader.go
│   ├── policy.go
│   ├── policy_test.go
│   └── ...
├── bpf/
│   ├── monitor.bpf.c
│   ├── xdp.bpf.c
│   └── vmlinux.h
├── dashboard/
│   └── React / TypeScript application
├── docs/
│   ├── CONFIGURATION.md
│   └── assets/
├── tests/
│   └── security_validation.sh
├── .github/workflows/
│   └── build.yml
├── Makefile
└── README.md
```

---

# Engineering Workflow

```
Change kernel instrumentation
          ↓
Generate / refresh kernel types
          ↓
Compile eBPF + XDP
          ↓
Run verifier validation
          ↓
Build Go agent
          ↓
Run unit + race tests
          ↓
Run controlled security behavior
          ↓
Inspect telemetry
          ↓
Validate detection
          ↓
Validate API / metrics
          ↓
Validate dashboard
          ↓
Document limitations
```

The project treats **implementation, verification, detection validation, performance testing, and documentation as separate engineering concerns**.

---

# Project Status

The active branch is:

```text
master
```

The current implementation includes:

- Kernel-level eBPF instrumentation
- Required and optional probe loading
- BTF-derived kernel types
- BPF ring-buffer transport
- Structured kernel/userspace event ABI
- Stateful behavioral correlation
- Security alert generation
- IPv4/IPv6 network telemetry
- Generic IP packet metadata
- Optional XDP Ethernet/L2 ingress telemetry
- VLAN-aware packet parsing
- Bounded IPv6 extension-header traversal
- Socket telemetry
- Expanded ATT&CK-aligned detection mappings
- Configurable detection policy
- Network event deduplication
- Container/cgroup context
- SIEM/SOAR webhook integration
- REST APIs
- Prometheus metrics
- React/TypeScript SOC dashboard
- Automated Linux CI
- Race/stress testing
- Performance benchmarks
- eBPF/XDP verifier validation

> **Production note:** This repository is a security-engineering and research implementation. Production EDR deployment would require broader kernel coverage, distribution/kernel compatibility testing, stronger privilege isolation, deployment-specific policy, long-duration load testing, and independent security validation.

---

# Live Evidence

The repository includes captured evidence from the telemetry and dashboard workflows.

![Agent Startup](docs/assets/Capture-Terminal.PNG)

![Continuous Alerts](docs/assets/Capture3.PNG)

![W^X Detection](docs/assets/Capture5.PNG)

![JSON Alert API](docs/assets/Capture4.PNG)

![Additional Capture](docs/assets/Capture2.PNG)

---

# License

MIT License. See [LICENSE](LICENSE).

## Author

**locallhosts**  
Linux Security · eBPF · Detection Engineering · Security Automation

[GitHub](https://github.com/locallhosts)
