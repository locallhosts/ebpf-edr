.PHONY: all bpf agent dashboard vmlinux clean run test-load

CLANG      ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -Ibpf
GO         ?= go

all: bpf agent

# Regenerate vmlinux.h from THIS machine's live kernel BTF. Run this
# once per target kernel version you build against - vmlinux.h is
# kernel-specific. Requires bpftool (package: linux-tools-common +
# linux-tools-$(uname -r), or linux-tools-generic on Ubuntu).
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compile the eBPF C program to a BPF ELF object. This is the artifact
# that gets embedded into the Go binary via go:embed.
bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/monitor.bpf.c -o bpf/monitor.bpf.o
	cp bpf/monitor.bpf.o agent/monitor.bpf.o

# Build the userspace agent. Requires bpf/monitor.bpf.o to already
# exist in agent/ (the `bpf` target does this for you).
agent: bpf
	cd agent && $(GO) build -o ../bin/edr-agent .

dashboard:
	cd dashboard && npm install && npm run build

# Load-check only: compiles and asks the kernel verifier to accept the
# program, then immediately unpins it. Useful in CI to catch a broken
# eBPF program without needing to run the full agent. Requires root.
test-load: bpf
	bpftool prog load bpf/monitor.bpf.o /sys/fs/bpf/edr_test_load
	@echo "verifier accepted the program"
	rm -f /sys/fs/bpf/edr_test_load

run: agent
	sudo ./bin/edr-agent -addr :9090

clean:
	rm -f bpf/monitor.bpf.o agent/monitor.bpf.o
	rm -rf bin dashboard/dist
