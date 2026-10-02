#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[1/6] Go static checks"
go vet ./agent
go test ./agent

echo "[2/6] Userspace race/stress tests"
go test -race ./agent

echo "[3/6] Performance benchmarks"
go test -bench=. -benchmem ./agent

echo "[4/6] eBPF/XDP compilation"
make bpf xdp

echo "[5/6] Source-level coverage assertions"
grep -q 'EVT_PACKET' bpf/xdp.bpf.c
grep -q 'EDR_XDP_INTERFACE' agent/loader.go
grep -q 'ringbuf_drops' bpf/monitor.bpf.c
grep -q 'next == 0 || next == 43 || next == 60 || next == 51' bpf/monitor.bpf.c
grep -q 'T1547.006' agent/detect.go
grep -q 'T1098.004' agent/detect.go

echo "[6/6] Kernel verifier/load validation"
if [[ "$(id -u)" -eq 0 ]] && command -v bpftool >/dev/null 2>&1; then
  make test-load
else
  echo "SKIP: verifier load test requires root and bpftool"
fi

echo "Security validation suite passed."
