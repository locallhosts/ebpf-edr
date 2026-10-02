// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVT_PACKET 16
#define FAM_INET 2
#define FAM_INET6 10
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_SCTP 132
#define PROTO_ICMPV6 58
#define DIR_INBOUND 1

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 128

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 type;
    __u32 alert_flags;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char argv0[MAX_ARGS_LEN];
    __u32 dst_addr;
    __u16 dst_port;
    __u32 target_pid;
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 _pad0;
    __u8 dst_addr6[16];
    __u32 src_addr;
    __u8 src_addr6[16];
    __u16 src_port;
    __u16 _pad1;
    __u32 old_uid;
    __u32 new_uid;
    __u32 sock_family;
    __u32 sock_type;
    __u32 packet_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} xdp_events SEC(".maps");

static __always_inline void emit(void *data, void *data_end, __u8 family, __u8 protocol,
                                  __u32 packet_len, void *src, void *dst,
                                  __u16 src_port, __u16 dst_port) {
    struct event *ev = bpf_ringbuf_reserve(&xdp_events, sizeof(*ev), 0);
    if (!ev) return;
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->type = EVT_PACKET;
    ev->family = family;
    ev->protocol = protocol;
    ev->direction = DIR_INBOUND;
    ev->packet_len = packet_len;
    __builtin_memcpy(ev->comm, "xdp", 4);
    if (family == FAM_INET) {
        __builtin_memcpy(&ev->src_addr, src, 4);
        __builtin_memcpy(&ev->dst_addr, dst, 4);
    } else {
        __builtin_memcpy(ev->src_addr6, src, 16);
        __builtin_memcpy(ev->dst_addr6, dst, 16);
    }
    ev->src_port = src_port;
    ev->dst_port = dst_port;
    bpf_ringbuf_submit(ev, 0);
}

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u32 l2 = sizeof(*eth);

    // Handle one VLAN tag so tagged traffic can still reach the L3 parser.
    if (proto == 0x8100 || proto == 0x88a8) {
        struct {
            __be16 tci;
            __be16 proto;
        } *vlan = data + l2;
        if ((void *)(vlan + 1) > data_end) return XDP_PASS;
        proto = bpf_ntohs(vlan->proto);
        l2 += 4;
    }

    void *network = data + l2;
    if (network > data_end) return XDP_PASS;
    __u32 packet_len = (__u32)((unsigned char *)data_end - (unsigned char *)data);

    if (proto == 0x0800) {
        struct iphdr *ip = network;
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        __u32 ihl = (__u32)(ip->ihl) * 4;
        if (ihl < 20 || network + ihl > data_end) return XDP_PASS;
        __u16 sp = 0, dp = 0;
        if (ip->protocol == PROTO_TCP || ip->protocol == PROTO_UDP || ip->protocol == PROTO_SCTP) {
            struct { __be16 src; __be16 dst; } *ports = network + ihl;
            if ((void *)(ports + 1) <= data_end) {
                sp = bpf_ntohs(ports->src);
                dp = bpf_ntohs(ports->dst);
            }
        }
        emit(data, data_end, FAM_INET, ip->protocol, packet_len,
             &ip->saddr, &ip->daddr, sp, dp);
        return XDP_PASS;
    }

    if (proto == 0x86dd) {
        struct ipv6hdr *ip6 = network;
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        __u8 next = ip6->nexthdr;
        __u32 cursor = sizeof(*ip6);
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (next == PROTO_TCP || next == PROTO_UDP || next == PROTO_SCTP || next == PROTO_ICMPV6) break;
            if (next == 44) {
                struct { __u8 nexthdr; __u8 reserved; __be16 frag_off; __be32 id; } *frag = network + cursor;
                if ((void *)(frag + 1) > data_end) return XDP_PASS;
                next = frag->nexthdr;
                cursor += 8;
                continue;
            }
            if (next == 0 || next == 43 || next == 60 || next == 51) {
                __u8 *hdr = network + cursor;
                if (hdr + 2 > (unsigned char *)data_end) return XDP_PASS;
                __u32 hdr_len = next == 51 ? ((__u32)hdr[1] + 2) * 4 : ((__u32)hdr[1] + 1) * 8;
                if (hdr_len < 8 || hdr_len > 256 || network + cursor + hdr_len > data_end) return XDP_PASS;
                next = hdr[0];
                cursor += hdr_len;
                continue;
            }
            break;
        }
        __u16 sp = 0, dp = 0;
        if (next == PROTO_TCP || next == PROTO_UDP || next == PROTO_SCTP) {
            struct { __be16 src; __be16 dst; } *ports = network + cursor;
            if ((void *)(ports + 1) <= data_end) {
                sp = bpf_ntohs(ports->src);
                dp = bpf_ntohs(ports->dst);
            }
        }
        emit(data, data_end, FAM_INET6, next, packet_len,
             &ip6->saddr, &ip6->daddr, sp, dp);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
