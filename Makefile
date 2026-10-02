.PHONY: all bpf xdp agent dashboard vmlinux clean run test-load test-validation test-perf

CLANG      ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -Ibpf
GO         ?= go

all: bpf xdp agent

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/monitor.bpf.c -o bpf/monitor.bpf.o
	cp bpf/monitor.bpf.o agent/monitor.bpf.o

xdp:
	$(CLANG) $(BPF_CFLAGS) -c bpf/xdp.bpf.c -o bpf/xdp.bpf.o
	cp bpf/xdp.bpf.o agent/xdp.bpf.o

agent: bpf xdp
	cd agent && $(GO) build -o ../bin/edr-agent .

dashboard:
	cd dashboard && npm install && npm run build

test-load: bpf xdp
	bpftool prog load bpf/monitor.bpf.o /sys/fs/bpf/edr_test_load
	@echo "tracepoint/kprobe verifier accepted the program"
	rm -f /sys/fs/bpf/edr_test_load
	bpftool prog load bpf/xdp.bpf.o /sys/fs/bpf/edr_xdp_test_load
	@echo "XDP verifier accepted the program"
	rm -f /sys/fs/bpf/edr_xdp_test_load

test-validation:
	bash tests/security_validation.sh

test-perf:
	go test -bench=. -benchmem ./agent

run: agent
	sudo ./bin/edr-agent -addr :9090

clean:
	rm -f bpf/monitor.bpf.o bpf/xdp.bpf.o agent/monitor.bpf.o agent/xdp.bpf.o
	rm -rf bin dashboard/dist
