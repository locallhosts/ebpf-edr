// SPDX-License-Identifier: GPL-2.0
//
// monitor.bpf.c (v4 - Privilege Escalation, Persistence, Rootkit & Fileless-Exec Detection)
//
// added full network visibility (IPv6/UDP/inbound/listen-setup).
// adds detection categories outside networking entirely:
//
//   - Privilege escalation to root      (commit_creds)
//   - Kernel module load (rootkits)     (init_module / finit_module)
//   - Unauthorized eBPF program loads   (bpf() syscall, BPF_PROG_LOAD)
//   - Fileless execution                (memfd_create -> execve of /proc/self/fd/N)
//   - Persistence writes                (cron, systemd units, authorized_keys,
//                                         ld.so.preload, sudoers, profile/bashrc, rc.local)
//   - Anti-forensics self-deletion      (unlink/unlinkat of a process's own binary)
//   - Namespace manipulation            (setns - container escape indicator)
//
// This version pushes detection logic INTO the kernel. By maintaining
// state in BPF maps and doing bounded loops in the kernel, we detect
// fileless malware, W^X bypasses, and reverse/bind shells with zero
// context switching to userspace.

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
#define EVT_EXEC          1
#define EVT_OPEN          2
#define EVT_CONNECT       3
#define EVT_PTRACE        4
#define EVT_MPROTECT      5
#define EVT_VM_WRITEV     6
#define EVT_ACCEPT        7
#define EVT_LISTEN        8
#define EVT_MODULE_LOAD   9  // NEW: init_module / finit_module
#define EVT_BPF           10 // NEW: bpf() syscall
#define EVT_PRIVESC       11 // NEW: commit_creds uid transition
#define EVT_MEMFD         12 // NEW: memfd_create
#define EVT_SOCKET_CREATE 13 // NEW: socket() syscall
#define EVT_UNLINK        14 // NEW: unlink/unlinkat
#define EVT_SETNS         15 // NEW: setns()

/* ---- Address family / protocol tags (mirrors Linux AF_*/IPPROTO_*) ---- */
#define FAM_INET       2   // AF_INET
#define FAM_INET6      10  // AF_INET6
#define FAM_PACKET     17  // AF_PACKET - raw sockets live here
#define PROTO_TCP      6   // IPPROTO_TCP
#define PROTO_UDP      17  // IPPROTO_UDP
#define SOCK_RAW_TYPE  3   // SOCK_RAW

/* ---- Direction ---- */
#define DIR_OUTBOUND   0
#define DIR_INBOUND    1

/* ---- BPF syscall commands we care about ---- */
#define BPF_PROG_LOAD_CMD 5

/* ---- Kernel-Space Alert Flags ---- */
#define ALERT_NONE                      0
#define ALERT_REVERSE_SHELL_LIKELY      (1 << 0)
#define ALERT_LD_PRELOAD_FOUND          (1 << 1)
#define ALERT_WX_BYPASS                 (1 << 2)
#define ALERT_CROSS_PROCESS_INJECT      (1 << 3)
#define ALERT_BIND_SHELL_LIKELY         (1 << 4)
#define ALERT_UNEXPECTED_LISTENER       (1 << 5)
#define ALERT_KERNEL_MODULE_LOAD        (1 << 6)  // NEW
#define ALERT_UNAUTHORIZED_BPF          (1 << 7)  // NEW
#define ALERT_PRIVESC_TO_ROOT           (1 << 8)  // NEW
#define ALERT_PERSISTENCE_WRITE         (1 << 9)  // NEW
#define ALERT_FILELESS_EXEC             (1 << 10) // NEW
#define ALERT_RAW_SOCKET                (1 << 11) // NEW
#define ALERT_SELF_DELETE               (1 << 12) // NEW
#define ALERT_NAMESPACE_MANIPULATION    (1 << 13) // NEW

/* Must match agent/events.go `Event` struct byte-for-byte.
 * v4 fields are appended at the end again, same reasoning as v3:
 * existing offsets for older fields never shift. */
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 type;
    __u32 alert_flags;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  argv0[MAX_ARGS_LEN];
    __u32 dst_addr;
    __u16 dst_port;
    __u32 target_pid;

    /* --- v3 fields --- */
    __u8  family;
    __u8  protocol;
    __u8  direction;
    __u8  _pad0;
    __u8  dst_addr6[16];
    __u32 src_addr;
    __u8  src_addr6[16];
    __u16 src_port;
    __u16 _pad1;

    /* --- v4 fields --- */
    __u32 old_uid;      // NEW: uid before a commit_creds transition
    __u32 new_uid;      // NEW: uid after a commit_creds transition
    __u32 sock_family;  // NEW: AF_* for socket() creation events
    __u32 sock_type;    // NEW: SOCK_* for socket() creation events
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

/* What binary a PID executed - powers reverse/bind shell correlation */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tgid
    __type(value, char[TASK_COMM_LEN]);
} exec_history SEC(".maps");

/* full exec path per tgid - powers self-delete (anti-forensics) detection */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tgid
    __type(value, char[MAX_FILENAME_LEN]);
} exec_paths SEC(".maps");

/* tgids that have called memfd_create - powers fileless-exec correlation */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tgid
    __type(value, __u8);
} memfd_pids SEC(".maps");

static __always_inline int is_shell_or_interpreter(const char *comm) {
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h') return 1;
    if (comm[0]=='s' && comm[1]=='h' && comm[2]==0) return 1;
    if (comm[0]=='z' && comm[1]=='s' && comm[2]=='h') return 1;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h') return 1;
    if (comm[0]=='p' && comm[1]=='e' && comm[2]=='r' && comm[3]=='l') return 1;
    if (comm[0]=='n' && comm[1]=='c' && comm[2]==0) return 1;
    return 0;
}

static __always_inline int check_ld_preload(const char *const *envp) {
    if (!envp) return 0;
    #pragma unroll
    for (int i = 0; i < 50; i++) {
        const char *env_var = NULL;
        if (bpf_probe_read_user(&env_var, sizeof(env_var), &envp[i]) != 0)
            return 0;
        if (!env_var)
            return 0;
        char prefix[12];
        if (bpf_probe_read_user_str(prefix, sizeof(prefix), env_var) != 11)
            continue;
        if (prefix[0]=='L' && prefix[1]=='D' && prefix[2]=='_' && prefix[3]=='P' &&
            prefix[4]=='R' && prefix[5]=='E' && prefix[6]=='L' && prefix[7]=='O' &&
            prefix[8]=='A' && prefix[9]=='D' && prefix[10]=='=') {
            return 1;
        }
    }
    return 0;
}

/* bounded startswith for known-length literal prefixes */
static __always_inline int path_startswith(const char *path, const char *prefix, int len) {
    #pragma unroll
    for (int i = 0; i < len; i++) {
        if (path[i] != prefix[i]) return 0;
    }
    return 1;
}

/* bounded substring search, capped window - for patterns that can
 * appear at a variable offset (e.g. "<homedir>/.ssh/authorized_keys") */
static __always_inline int path_contains(const char *hay, const char *needle, int needle_len) {
    #pragma unroll
    for (int i = 0; i < 96; i++) {
        int match = 1;
        #pragma unroll
        for (int j = 0; j < needle_len; j++) {
            if (hay[i + j] != needle[j]) { match = 0; break; }
            if (hay[i + j] == 0) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

/* is this a known persistence path being written to? */
static __always_inline int is_persistence_path(const char *path) {
    if (path_startswith(path, "/etc/cron", 9)) return 1;
    if (path_startswith(path, "/etc/systemd/system/", 20)) return 1;
    if (path_startswith(path, "/etc/ld.so.preload", 18)) return 1;
    if (path_startswith(path, "/etc/rc.local", 13)) return 1;
    if (path_startswith(path, "/etc/sudoers", 12)) return 1;
    if (path_startswith(path, "/etc/profile", 12)) return 1;
    if (path_startswith(path, "/etc/bash.bashrc", 16)) return 1;
    if (path_contains(path, ".ssh/authorized_keys", 20)) return 1;
    return 0;
}

/* fileless-exec indicator - execve target living under /proc/*/fd/ or
 * /dev/fd/ or /memfd: means the code being run has no path on disk. */
static __always_inline int is_fileless_exec_target(const char *path) {
    if (path_startswith(path, "/proc/self/fd/", 14)) return 1;
    if (path_startswith(path, "/dev/fd/", 8)) return 1;
    if (path_contains(path, "memfd:", 6)) return 1;
    return 0;
}

static __always_inline struct event *get_scratch_event(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scratch, &zero);
}

static __always_inline void fill_common(struct event *ev, __u32 type) {
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->tgid = id >> 32;
    ev->pid  = (__u32)id;
    ev->uid  = (__u32)bpf_get_current_uid_gid();
    ev->type = type;
    ev->alert_flags = ALERT_NONE;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline void submit_event(struct event *ev) {
    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return;
    __builtin_memcpy(out, ev, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
}

static __always_inline int comm_is_shell(struct event *ev) {
    return is_shell_or_interpreter(ev->comm);
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

    if (check_ld_preload(ctx->envp)) {
        ev->alert_flags |= ALERT_LD_PRELOAD_FOUND;
    }

    __u32 tgid = ev->tgid;
    bpf_map_update_elem(&exec_history, &tgid, &ev->comm, BPF_ANY);
    bpf_map_update_elem(&exec_paths, &tgid, &ev->filename, BPF_ANY);

    // --- Fileless execution detection ---
    // Either the exec target path itself looks fileless (/proc/self/fd/N,
    // /dev/fd/N, memfd:...), or this tgid previously called memfd_create
    // and is now exec'ing (classic "write payload to memfd, fexecve it" flow).
    __u8 *memfd_flag = bpf_map_lookup_elem(&memfd_pids, &tgid);
    if (is_fileless_exec_target(ev->filename) || memfd_flag) {
        ev->alert_flags |= ALERT_FILELESS_EXEC;
    }

    submit_event(ev);
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

#define O_WRONLY_FLAG 00000001
#define O_RDWR_FLAG   00000002
#define O_CREAT_FLAG  00000100

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_OPEN);
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), ctx->filename);

    // : Persistence-write hunting ---
    // Only fire when the open is for writing/creating - read-only opens of
    // these paths (e.g. `cat /etc/crontab`) are routine and not persistence.
    int writeish = (ctx->flags & (O_WRONLY_FLAG | O_RDWR_FLAG | O_CREAT_FLAG)) != 0;
    if (writeish && is_persistence_path(ev->filename)) {
        ev->alert_flags |= ALERT_PERSISTENCE_WRITE;
    }

    submit_event(ev);
    return 0;
}

/* ============================================================
 * Kernel module load (rootkit installation)
 * ============================================================ */
struct trace_event_raw_sys_enter_init_module {
    __u64 unused;
    long syscall_nr;
    void *umod;
    unsigned long len;
    const char *uargs;
};

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter_init_module *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_MODULE_LOAD);
    ev->alert_flags |= ALERT_KERNEL_MODULE_LOAD;
    submit_event(ev);
    return 0;
}

struct trace_event_raw_sys_enter_finit_module {
    __u64 unused;
    long syscall_nr;
    long fd;
    const char *uargs;
    long flags;
};

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter_finit_module *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_MODULE_LOAD);
    ev->alert_flags |= ALERT_KERNEL_MODULE_LOAD;
    submit_event(ev);
    return 0;
}

/* ============================================================
 * eBPF self-defense: watch for other programs loading BPF
 *
 * NOTE: this will also see the EDR agent's own BPF_PROG_LOAD calls
 * at startup. Filter your own agent's pid/comm out in userspace
 * (agent/detect.go) rather than trying to special-case it here -
 * the kernel side doesn't know its own userspace pid at compile time.
 * ============================================================ */
struct trace_event_raw_sys_enter_bpf {
    __u64 unused;
    long syscall_nr;
    long cmd;
    void *attr;
    long size;
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter_bpf *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_BPF);

    if (ctx->cmd == BPF_PROG_LOAD_CMD) {
        ev->alert_flags |= ALERT_UNAUTHORIZED_BPF;
    }

    submit_event(ev);
    return 0;
}

/* ============================================================
 * Privilege escalation to root
 *
 * commit_creds(struct cred *new) is the single choke point the
 * kernel uses to actually switch a task's credentials. Comparing
 * the calling task's current uid (still old at kprobe entry)
 * against the incoming cred's uid catches privilege escalation
 * regardless of *how* it happened - setuid binary, sudo, a kernel
 * exploit, capability abuse, etc. A jump straight to uid 0 from a
 * non-root, non-setuid-sanctioned context is one of the highest
 * signal indicators available in the kernel.
 * ============================================================ */
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new) {
    __u32 old_uid = (__u32)bpf_get_current_uid_gid();
    __u32 new_uid = 0;
    BPF_CORE_READ_INTO(&new_uid, new, uid.val);

    // Only emit when something interesting actually changes -
    // avoids flooding the ring buffer on every fork/clone's routine
    // cred copy where old_uid == new_uid.
    if (old_uid == new_uid) return 0;

    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_PRIVESC);
    ev->old_uid = old_uid;
    ev->new_uid = new_uid;

    if (old_uid != 0 && new_uid == 0) {
        ev->alert_flags |= ALERT_PRIVESC_TO_ROOT;
    }

    submit_event(ev);
    return 0;
}

/* ============================================================
 * memfd_create: sets up fileless-exec correlation
 * ============================================================ */
struct trace_event_raw_sys_enter_memfd_create {
    __u64 unused;
    long syscall_nr;
    const char *uname;
    long flags;
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter_memfd_create *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_MEMFD);
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), ctx->uname);

    __u32 tgid = ev->tgid;
    __u8 one = 1;
    bpf_map_update_elem(&memfd_pids, &tgid, &one, BPF_ANY);

    submit_event(ev);
    return 0;
}

/* ============================================================
 * Raw / packet socket creation
 *
 * AF_PACKET or SOCK_RAW sockets are needed for packet sniffing,
 * ARP spoofing, and crafting spoofed packets - legitimate for tools
 * like tcpdump, but rare and worth a look from anything else.
 * ============================================================ */
struct trace_event_raw_sys_enter_socket {
    __u64 unused;
    long syscall_nr;
    long family;
    long type;
    long protocol;
};

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter_socket *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_SOCKET_CREATE);
    ev->sock_family = (__u32)ctx->family;
    ev->sock_type = (__u32)(ctx->type & 0xFF); // low byte, mask off SOCK_NONBLOCK/SOCK_CLOEXEC

    if (ctx->family == FAM_PACKET || ev->sock_type == SOCK_RAW_TYPE) {
        ev->alert_flags |= ALERT_RAW_SOCKET;
    }

    submit_event(ev);
    return 0;
}

/* ============================================================
 * Anti-forensics: self-deletion of a running binary
 *
 * Malware frequently unlinks its own on-disk file right after
 * exec to defeat static forensic analysis while continuing to
 * run from the inode/page cache. We compare the unlink target
 * against the path this tgid originally exec'd.
 * ============================================================ */
struct trace_event_raw_sys_enter_unlinkat {
    __u64 unused;
    long syscall_nr;
    long dfd;
    const char *pathname;
    long flag;
};

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter_unlinkat *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_UNLINK);
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), ctx->pathname);

    __u32 tgid = ev->tgid;
    char *exec_path = bpf_map_lookup_elem(&exec_paths, &tgid);
    if (exec_path) {
        // Bounded compare over a reasonable prefix window - full-length
        // dynamic compare isn't verifier-friendly, but a self-delete
        // targets the exact exec path, so a prefix match is reliable
        // enough here without needing unbounded string length logic.
        if (path_startswith(ev->filename, exec_path, 32)) {
            ev->alert_flags |= ALERT_SELF_DELETE;
        }
    }

    submit_event(ev);
    return 0;
}

/* ============================================================
 *  Namespace manipulation escape indicator)
 * ============================================================ */
struct trace_event_raw_sys_enter_setns {
    __u64 unused;
    long syscall_nr;
    long fd;
    long nstype;
};

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter_setns *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_SETNS);
    ev->alert_flags |= ALERT_NAMESPACE_MANIPULATION;
    submit_event(ev);
    return 0;
}

/* ============================================================
 * Network hooks 
 * ============================================================ */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect_v4, struct sock *sk) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_CONNECT);
    ev->family = FAM_INET;
    ev->protocol = PROTO_TCP;
    ev->direction = DIR_OUTBOUND;

    __u32 dst_addr = 0;
    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_addr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    ev->dst_addr = dst_addr;
    ev->dst_port = bpf_ntohs(dst_port);

    __u32 tgid = ev->tgid;
    char *saved_comm = bpf_map_lookup_elem(&exec_history, &tgid);
    if (saved_comm && is_shell_or_interpreter(saved_comm)) {
        ev->alert_flags |= ALERT_REVERSE_SHELL_LIKELY;
    }
    submit_event(ev);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_connect_v6, struct sock *sk) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_CONNECT);
    ev->family = FAM_INET6;
    ev->protocol = PROTO_TCP;
    ev->direction = DIR_OUTBOUND;

    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    ev->dst_port = bpf_ntohs(dst_port);
    BPF_CORE_READ_INTO(&ev->dst_addr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

    __u32 tgid = ev->tgid;
    char *saved_comm = bpf_map_lookup_elem(&exec_history, &tgid);
    if (saved_comm && is_shell_or_interpreter(saved_comm)) {
        ev->alert_flags |= ALERT_REVERSE_SHELL_LIKELY;
    }
    submit_event(ev);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_CONNECT);
    ev->family = FAM_INET;
    ev->protocol = PROTO_UDP;
    ev->direction = DIR_OUTBOUND;

    __u32 dst_addr = 0;
    __u16 dst_port = 0;
    void *msg_name = NULL;
    int msg_namelen = 0;
    BPF_CORE_READ_INTO(&msg_name, msg, msg_name);
    BPF_CORE_READ_INTO(&msg_namelen, msg, msg_namelen);

    if (msg_name && msg_namelen >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr = {};
        bpf_core_read(&addr, sizeof(addr), msg_name);
        dst_addr = addr.sin_addr.s_addr;
        dst_port = bpf_ntohs(addr.sin_port);
    } else {
        BPF_CORE_READ_INTO(&dst_addr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
        dst_port = bpf_ntohs(dst_port);
    }
    ev->dst_addr = dst_addr;
    ev->dst_port = dst_port;

    __u32 tgid = ev->tgid;
    char *saved_comm = bpf_map_lookup_elem(&exec_history, &tgid);
    if (saved_comm && is_shell_or_interpreter(saved_comm)) {
        ev->alert_flags |= ALERT_REVERSE_SHELL_LIKELY;
    }
    submit_event(ev);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg, struct sock *sk, struct msghdr *msg) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_CONNECT);
    ev->family = FAM_INET6;
    ev->protocol = PROTO_UDP;
    ev->direction = DIR_OUTBOUND;

    void *msg_name = NULL;
    int msg_namelen = 0;
    BPF_CORE_READ_INTO(&msg_name, msg, msg_name);
    BPF_CORE_READ_INTO(&msg_namelen, msg, msg_namelen);

    if (msg_name && msg_namelen >= (int)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 addr = {};
        bpf_core_read(&addr, sizeof(addr), msg_name);
        __builtin_memcpy(ev->dst_addr6, &addr.sin6_addr, 16);
        ev->dst_port = bpf_ntohs(addr.sin6_port);
    } else {
        BPF_CORE_READ_INTO(&ev->dst_addr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        __u16 dst_port = 0;
        BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
        ev->dst_port = bpf_ntohs(dst_port);
    }

    __u32 tgid = ev->tgid;
    char *saved_comm = bpf_map_lookup_elem(&exec_history, &tgid);
    if (saved_comm && is_shell_or_interpreter(saved_comm)) {
        ev->alert_flags |= ALERT_REVERSE_SHELL_LIKELY;
    }
    submit_event(ev);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inet_csk_accept, struct sock *sk) {
    if (!sk) return 0;
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_ACCEPT);
    ev->protocol = PROTO_TCP;
    ev->direction = DIR_INBOUND;

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    ev->dst_port = bpf_ntohs(dst_port);

    if (family == FAM_INET6) {
        ev->family = FAM_INET6;
        BPF_CORE_READ_INTO(&ev->dst_addr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        ev->family = FAM_INET;
        BPF_CORE_READ_INTO(&ev->dst_addr, sk, __sk_common.skc_daddr);
    }

    __u16 src_port = 0;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    ev->src_port = src_port;

    if (comm_is_shell(ev)) {
        ev->alert_flags |= ALERT_BIND_SHELL_LIKELY;
    }
    submit_event(ev);
    return 0;
}

SEC("kprobe/inet_csk_listen_start")
int BPF_KPROBE(trace_listen_start, struct sock *sk) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_LISTEN);
    ev->direction = DIR_INBOUND;

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    ev->family = (family == FAM_INET6) ? FAM_INET6 : FAM_INET;
    ev->protocol = PROTO_TCP;

    __u16 src_port = 0;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    ev->src_port = src_port;

    if (comm_is_shell(ev)) {
        ev->alert_flags |= ALERT_UNEXPECTED_LISTENER;
    }
    submit_event(ev);
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
    submit_event(ev);
    return 0;
}

struct trace_event_raw_sys_enter_mprotect {
    __u64 unused;
    long syscall_nr;
    unsigned long addr;
    size_t len;
    long prot;
};

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter_mprotect *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_MPROTECT);
    if ((ctx->prot & 0x6) == 0x6) {
        ev->alert_flags |= ALERT_WX_BYPASS;
    }
    submit_event(ev);
    return 0;
}

struct trace_event_raw_sys_enter_process_vm_writev {
    __u64 unused;
    long syscall_nr;
    long pid;
};

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_process_vm_writev(struct trace_event_raw_sys_enter_process_vm_writev *ctx) {
    struct event *ev = get_scratch_event();
    if (!ev) return 0;
    fill_common(ev, EVT_VM_WRITEV);
    ev->target_pid = (__u32)ctx->pid;
    if (ev->target_pid != 0 && ev->target_pid != ev->tgid) {
        ev->alert_flags |= ALERT_CROSS_PROCESS_INJECT;
    }
    submit_event(ev);
    return 0;
}
