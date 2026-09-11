package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "strings"
)

// Event type tags — MUST match bpf/monitor.bpf.c #define EVT_* exactly.
const (
    EvtExec      uint32 = 1
    EvtOpen      uint32 = 2
    EvtConnect   uint32 = 3
    EvtPtrace    uint32 = 4
    EvtMprotect  uint32 = 5 // NEW
    EvtVmWritev  uint32 = 6 // NEW
)

// Alert flag constants — MUST match bpf/monitor.bpf.c #define ALERT_* exactly.
const (
    AlertNone                uint32 = 0
    AlertReverseShellLikely  uint32 = 1 << 0
    AlertLdPreloadFound      uint32 = 1 << 1
    AlertWxBypass            uint32 = 1 << 2
    AlertCrossProcessInject  uint32 = 1 << 3
)

const (
    taskCommLen    = 16
    maxFilenameLen = 256
    maxArgsLen     = 128
)

// rawEvent mirrors `struct event` in bpf/monitor.bpf.c byte-for-byte.
type rawEvent struct {
    TimestampNs uint64
    Pid         uint32
    Tgid        uint32
    Ppid        uint32
    Uid         uint32
    Type        uint32
    AlertFlags  uint32 // NEW: Inserted right after Type
    Comm        [taskCommLen]byte
    Filename    [maxFilenameLen]byte
    Argv0       [maxArgsLen]byte
    DstAddr     uint32
    DstPort     uint16
    _           uint16 // padding to keep TargetPid 4-byte aligned
    TargetPid   uint32
}

// Event is the decoded, Go-friendly representation.
type Event struct {
    TimestampNs uint64
    Pid         uint32
    Tgid        uint32
    Ppid        uint32
    Uid         uint32
    Type        uint32
    AlertFlags  uint32 // NEW
    Comm        string
    Filename    string
    Argv0       string
    DstAddr     net.IP
    DstPort     uint16
    TargetPid   uint32
}

func (e Event) TypeName() string {
    switch e.Type {
    case EvtExec:
        return "EXEC"
    case EvtOpen:
        return "OPEN"
    case EvtConnect:
        return "CONNECT"
    case EvtPtrace:
        return "PTRACE"
    case EvtMprotect:
        return "MPROTECT" // NEW
    case EvtVmWritev:
        return "VM_WRITEV" // NEW
    default:
        return "UNKNOWN"
    }
}

// DecodeAlerts translates the kernel-space bitmask into a readable string.
func (e Event) DecodeAlerts() string {
    if e.AlertFlags == AlertNone {
        return "NONE"
    }
    var alerts []string
    if e.AlertFlags&AlertReverseShellLikely != 0 {
        alerts = append(alerts, "REVERSE_SHELL_LIKELY")
    }
    if e.AlertFlags&AlertLdPreloadFound != 0 {
        alerts = append(alerts, "LD_PRELOAD_FOUND")
    }
    if e.AlertFlags&AlertWxBypass != 0 {
        alerts = append(alerts, "WX_BYPASS")
    }
    if e.AlertFlags&AlertCrossProcessInject != 0 {
        alerts = append(alerts, "CROSS_PROCESS_INJECT")
    }
    return strings.Join(alerts, ", ")
}

// IsMalicious is a helper for the Go detection engine to quickly filter
func (e Event) IsMalicious() bool {
    return e.AlertFlags != AlertNone
}

func cString(b []byte) string {
    for i, c := range b {
        if c == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}

// parseEvent decodes a raw ring buffer record into an Event.
func parseEvent(raw []byte) (Event, error) {
    // Updated expected size: 8 (ts) + 6*4 (uint32s) + 16 + 256 + 128 + 4 + 2 + 2 (pad) + 4
    // = 8 + 24 + 400 + 8 = 440 bytes
    const expectedSize = 8 + 4*6 + taskCommLen + maxFilenameLen + maxArgsLen + 4 + 2 + 2 + 4
    if len(raw) < expectedSize {
        return Event{}, fmt.Errorf("short ring buffer record: got %d bytes, want >= %d", len(raw), expectedSize)
    }

    off := 0
    readU64 := func() uint64 {
        v := binary.LittleEndian.Uint64(raw[off:])
        off += 8
        return v
    }
    readU32 := func() uint32 {
        v := binary.LittleEndian.Uint32(raw[off:])
        off += 4
        return v
    }
    readU16 := func() uint16 {
        v := binary.LittleEndian.Uint16(raw[off:])
        off += 2
        return v
    }
    readBytes := func(n int) []byte {
        b := raw[off : off+n]
        off += n
        return b
    }

    ev := Event{}
    ev.TimestampNs = readU64()
    ev.Pid = readU32()
    ev.Tgid = readU32()
    ev.Ppid = readU32()
    ev.Uid = readU32()
    ev.Type = readU32()
    ev.AlertFlags = readU32() // NEW: Read the alert bitmask
    ev.Comm = cString(readBytes(taskCommLen))
    ev.Filename = cString(readBytes(maxFilenameLen))
    ev.Argv0 = cString(readBytes(maxArgsLen))

    dstAddrRaw := readU32()
    // skc_daddr is stored network-byte-order in the kernel already.
    addrBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(addrBytes, binary.BigEndian.Uint32([]byte{
        byte(dstAddrRaw), byte(dstAddrRaw >> 8), byte(dstAddrRaw >> 16), byte(dstAddrRaw >> 24),
    }))
    ev.DstAddr = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])

    ev.DstPort = readU16()
    _ = readU16() // padding
    ev.TargetPid = readU32()

    return ev, nil
}