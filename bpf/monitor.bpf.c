// SPDX-License-Identifier: GPL-2.0
//
// monitor.bpf.c (v2 - Advanced Kernel-Space Threat Hunting)
//
// This version pushes detection logic INTO the kernel. By maintaining
// state in BPF maps and doing bounded loops in the kernel, we detect
// fileless malware, W^X bypasses, and reverse shells with zero context
// switching to userspace.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN   16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN    128

/* ---- Event type tags ---- */
#define EVT_EXEC        1
#define EVT_OPEN        2
#define EVT_CONNECT     3
#define EVT_PTRACE      4
#define EVT_MPROTECT    5
#define EVT_VM_WRITEV   6

/* ---- Advanced Kernel-Space Alert Flags ---- */
#define ALERT_NONE                  0
#define ALERT_REVERSE_SHELL_LIKELY  (1 << 0) // A shell connected to a remote IP
#define ALERT_LD_PRELOAD_FOUND      (1 << 1) // Process spawned with LD_PRELOAD
#define ALERT_WX_BYPASS             (1 << 2) // mprotect called with PROT_WRITE | PROT_EXEC
#define ALERT_CROSS_PROCESS_INJECT  (1 << 3) // process_vm_writev called on another PID

/* Must match agent/events.go `Event` struct byte-for-byte */
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 type;
    __u32 alert_flags;             // NEW: Kernel-populated alert bitmask
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN]; 
    char argv0[MAX_ARGS_LEN];        
    __u32 dst_addr;                  
    __u16 dst_port;                  
    __u32 target_pid;                
};

/* Ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Per-CPU scratch space */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

/* NEW: Map to remember what binary a PID executed, for reverse shell correlation */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // pid_tgid
    __type(value, char[TASK_COMM_LEN]);
} exec_history SEC(".maps");

/* Helper to check if a comm is a known shell/script interpreter */
static __always_inline int is_shell_or_interpreter(const char *comm) {
    // Bounded string comparisons to satisfy eBPF verifier
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h') return 1;
    if (comm[0]=='s' && comm[1]=='h' && comm[2]==0) return 1;
    if (comm[0]=='z' && comm[1]=='s' && comm[2]=='h') return 1;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h') return 1; 
    if (comm[0]=='p' && comm[1]=='e' && comm[2]=='r' && comm[3]=='l') return 1;
    if (comm[0]=='n' && comm[1]=='c' && comm[2]==0) return 1;
    return 0;
}

/* NEW: Helper to safely iterate envp looking for LD_PRELOAD */
static __always_inline int check_ld_preload(const char *const *envp) {
    if (!envp) return 0;
    
    // BPF verifier requires bounded loops. 50 env vars is a safe upper limit.
    #pragma unroll
    for (int i = 0; i < 50; i++) {
        const char *env_var = NULL;
        if (bpf_probe_read_user(&env_var, sizeof(env_var), &envp[i]) != 0)
            return 0; // Read failed, likely end of array
        
        if (!env_var)
            return 0; // Null terminator found

        // Read first 11 bytes to check for "LD_PRELOAD="
        char prefix[12];
        if (bpf_probe_read_user_str(prefix, sizeof(prefix), env_var) != 11)
            continue; // Not long enough
        
        if (prefix[0]=='L' && prefix[1]=='D' && prefix[2]=='_' && prefix[3]=='P' && 
            prefix[4]=='R' && prefix[5]=='E' && prefix[6]=='L' && prefix[7]=='O' && 
            prefix[8]=='A' && prefix[9]=='D' && prefix[10]=='=') {
            return 1; // Found it!
        }
    }
    return 0;
}

static __always_inline struct event *get_scratch_event(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scratch, &zero);
}

static __always_inline void fill_common(struct event *ev, __u32 type) {
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->tgid = id >> 32;
    ev->pid = (__u32)id;
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->type = type;
    ev->alert_flags = ALERT_NONE; // Initialize to zero
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

struct trace_event_raw_sys_enter_execve {
    __u64 unused;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_EXEC);
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), ctx->filename);

    const char *argv0_ptr = NULL;
    bpf_probe_read_user(&argv0_ptr, sizeof(argv0_ptr), &ctx->argv[0]);
    if (argv0_ptr)
        bpf_probe_read_user_str(&ev->argv0, sizeof(ev->argv0), argv0_ptr);

    // --- ADVANCED DETECTION 1: LD_PRELOAD Hunting ---
    if (check_ld_preload(ctx->envp)) {
        ev->alert_flags |= ALERT_LD_PRELOAD_FOUND;
    }

    // Save to exec_history for reverse shell correlation
    __u32 pid_tgid = ev->tgid; // Use tgid as key
    bpf_map_update_elem(&exec_history, &pid_tgid, &ev->comm, BPF_ANY);

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

struct trace_event_raw_sys_enter_openat {
    __u64 unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_OPEN);
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), ctx->filename);

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect, struct sock *sk) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_CONNECT);

    __u32 dst_addr = 0;
    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_addr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);

    ev->dst_addr = dst_addr;
    ev->dst_port = bpf_ntohs(dst_port);

    // --- ADVANCED DETECTION 2: Kernel-Space Reverse Shell Correlation ---
    __u32 pid_tgid = ev->tgid;
    char *saved_comm = bpf_map_lookup_elem(&exec_history, &pid_tgid);
    if (saved_comm) {
        if (is_shell_or_interpreter(saved_comm)) {
            // A shell/script just opened an outbound network connection!
            ev->alert_flags |= ALERT_REVERSE_SHELL_LIKELY;
        }
    }

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

struct trace_event_raw_sys_enter_ptrace {
    __u64 unused;
    long syscall_nr;
    long request;
    long pid;
    long addr;
    long data;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter_ptrace *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_PTRACE);
    ev->target_pid = (__u32)ctx->pid;

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

/* NEW: mprotect tracepoint for W^X bypass detection */
struct trace_event_raw_sys_enter_mprotect {
    __u64 unused;
    long syscall_nr;
    unsigned long addr;
    size_t len;
    long prot; // Protection flags
};

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter_mprotect *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_MPROTECT);

    // --- ADVANCED DETECTION 3: W^X (Write-Execute) Bypass ---
    // PROT_WRITE = 0x2, PROT_EXEC = 0x4
    if ((ctx->prot & 0x6) == 0x6) {
        ev->alert_flags |= ALERT_WX_BYPASS;
    }

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

/* NEW: process_vm_writev tracepoint for cross-process injection */
struct trace_event_raw_sys_enter_process_vm_writev {
    __u64 unused;
    long syscall_nr;
    long pid; // Target process ID
    // ... rest of args omitted for brevity
};

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_process_vm_writev(struct trace_event_raw_sys_enter_process_vm_writev *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;

    fill_common(ev, EVT_VM_WRITEV);
    ev->target_pid = (__u32)ctx->pid;

    // ---  4: Cross-Process Injection ---
    if (ev->target_pid != 0 && ev->target_pid != ev->tgid) {
        // Writing to memory of a DIFFERENT process
        ev->alert_flags |= ALERT_CROSS_PROCESS_INJECT;
    }

    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}