package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "strings"
)

// Event type tags — MUST match bpf/monitor.bpf.c.
const (
    EvtExec         uint32 = 1
    EvtOpen         uint32 = 2
    EvtConnect      uint32 = 3
    EvtPtrace       uint32 = 4
    EvtMprotect     uint32 = 5
    EvtVmWritev     uint32 = 6
    EvtAccept       uint32 = 7
    EvtListen       uint32 = 8
    EvtModuleLoad   uint32 = 9
    EvtBPF          uint32 = 10
    EvtPrivEsc      uint32 = 11
    EvtMemFD        uint32 = 12
    EvtSocketCreate uint32 = 13
    EvtUnlink       uint32 = 14
    EvtSetNS        uint32 = 15
    EvtPacket       uint32 = 16
)

const (
    AlertNone                 uint32 = 0
    AlertReverseShellLikely   uint32 = 1 << 0
    AlertLdPreloadFound       uint32 = 1 << 1
    AlertWxBypass             uint32 = 1 << 2
    AlertCrossProcessInject   uint32 = 1 << 3
    AlertBindShellLikely      uint32 = 1 << 4
    AlertUnexpectedListener   uint32 = 1 << 5
    AlertKernelModuleLoad     uint32 = 1 << 6
    AlertUnauthorizedBPF      uint32 = 1 << 7
    AlertPrivEscToRoot        uint32 = 1 << 8
    AlertPersistenceWrite     uint32 = 1 << 9
    AlertFilelessExec         uint32 = 1 << 10
    AlertRawSocket            uint32 = 1 << 11
    AlertSelfDelete           uint32 = 1 << 12
    AlertNamespaceManipulation uint32 = 1 << 13
)

const (
    FamilyIPv4 = 2
    FamilyIPv6 = 10

    ProtocolICMP   = 1
    ProtocolTCP    = 6
    ProtocolUDP    = 17
    ProtocolICMPv6 = 58
    ProtocolSCTP   = 132
)

const (
    DirectionOutbound uint8 = 0
    DirectionInbound  uint8 = 1

    taskCommLen    = 16
    maxFilenameLen = 256
    maxArgsLen     = 128
)

// Event mirrors struct event in bpf/monitor.bpf.c.
// The parser intentionally follows the kernel ABI field-by-field.
type Event struct {
    TimestampNs uint64
    Pid         uint32
    Tgid        uint32
    Ppid        uint32
    Uid         uint32
    Type        uint32
    AlertFlags  uint32
    Comm        string
    Filename    string
    Argv0       string

    DstAddr  net.IP
    DstAddr6 net.IP
    SrcAddr  net.IP
    SrcAddr6 net.IP
    DstPort  uint16
    SrcPort  uint16
    TargetPid uint32

    Family    uint8
    Protocol  uint8
    Direction uint8

    OldUID     uint32
    NewUID     uint32
    SockFamily uint32
    SockType   uint32
    PacketLen  uint32
}

func (e Event) TypeName() string {
    switch e.Type {
    case EvtExec:         return "EXEC"
    case EvtOpen:         return "OPEN"
    case EvtConnect:      return "CONNECT"
    case EvtPtrace:       return "PTRACE"
    case EvtMprotect:     return "MPROTECT"
    case EvtVmWritev:     return "VM_WRITEV"
    case EvtAccept:       return "ACCEPT"
    case EvtListen:       return "LISTEN"
    case EvtModuleLoad:   return "MODULE_LOAD"
    case EvtBPF:          return "BPF_LOAD"
    case EvtPrivEsc:      return "PRIVESC"
    case EvtMemFD:        return "MEMFD"
    case EvtSocketCreate: return "SOCKET"
    case EvtUnlink:       return "UNLINK"
    case EvtSetNS:        return "SETNS"
    case EvtPacket:       return "PACKET"
    default:              return "UNKNOWN"
    }
}

func (e Event) ProtocolName() string {
    switch e.Protocol {
    case ProtocolICMP:   return "ICMP"
    case ProtocolTCP:    return "TCP"
    case ProtocolUDP:    return "UDP"
    case ProtocolICMPv6: return "ICMPv6"
    case ProtocolSCTP:   return "SCTP"
    case 0:              return "UNKNOWN"
    default:             return fmt.Sprintf("IP/%d", e.Protocol)
    }
}

func (e Event) FamilyName() string {
    switch e.Family {
    case FamilyIPv4: return "IPv4"
    case FamilyIPv6: return "IPv6"
    default:         return "AF_UNKNOWN"
    }
}

func (e Event) DirectionName() string {
    if e.Direction == DirectionInbound {
        return "INBOUND"
    }
    return "OUTBOUND"
}

func (e Event) NetworkEvent() bool {
    return e.Type == EvtConnect || e.Type == EvtAccept || e.Type == EvtListen || e.Type == EvtPacket || e.Type == EvtSocketCreate
}

func (e Event) DecodeAlerts() string {
    if e.AlertFlags == AlertNone {
        return "NONE"
    }
    checks := []struct {
        flag uint32
        name string
    }{
        {AlertReverseShellLikely, "REVERSE_SHELL_LIKELY"},
        {AlertLdPreloadFound, "LD_PRELOAD_FOUND"},
        {AlertWxBypass, "WX_BYPASS"},
        {AlertCrossProcessInject, "CROSS_PROCESS_INJECT"},
        {AlertBindShellLikely, "BIND_SHELL_LIKELY"},
        {AlertUnexpectedListener, "UNEXPECTED_LISTENER"},
        {AlertKernelModuleLoad, "KERNEL_MODULE_LOAD"},
        {AlertUnauthorizedBPF, "UNAUTHORIZED_BPF"},
        {AlertPrivEscToRoot, "PRIVESC_TO_ROOT"},
        {AlertPersistenceWrite, "PERSISTENCE_WRITE"},
        {AlertFilelessExec, "FILELESS_EXEC"},
        {AlertRawSocket, "RAW_SOCKET"},
        {AlertSelfDelete, "SELF_DELETE"},
        {AlertNamespaceManipulation, "NAMESPACE_MANIPULATION"},
    }
    var alerts []string
    for _, c := range checks {
        if e.AlertFlags&c.flag != 0 {
            alerts = append(alerts, c.name)
        }
    }
    return strings.Join(alerts, ", ")
}

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

func ipv4FromRaw(v uint32) net.IP {
    return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func ipv6FromRaw(b []byte) net.IP {
    if len(b) != net.IPv6len {
        return nil
    }
    out := make(net.IP, net.IPv6len)
    copy(out, b)
    return out
}

// parseEvent decodes the current v4 event ABI (504 bytes on 64-bit Linux).
func parseEvent(raw []byte) (Event, error) {
    const expectedSize = 512
    if len(raw) < expectedSize {
        return Event{}, fmt.Errorf("short ring buffer record: got %d bytes, want >= %d", len(raw), expectedSize)
    }

    off := 0
    readU64 := func() uint64 { v := binary.LittleEndian.Uint64(raw[off:]); off += 8; return v }
    readU32 := func() uint32 { v := binary.LittleEndian.Uint32(raw[off:]); off += 4; return v }
    readU16 := func() uint16 { v := binary.LittleEndian.Uint16(raw[off:]); off += 2; return v }
    readU8 := func() uint8 { v := raw[off]; off++; return v }
    readBytes := func(n int) []byte { b := raw[off:off+n]; off += n; return b }

    ev := Event{}
    ev.TimestampNs = readU64()
    ev.Pid = readU32()
    ev.Tgid = readU32()
    ev.Ppid = readU32()
    ev.Uid = readU32()
    ev.Type = readU32()
    ev.AlertFlags = readU32()
    ev.Comm = cString(readBytes(taskCommLen))
    ev.Filename = cString(readBytes(maxFilenameLen))
    ev.Argv0 = cString(readBytes(maxArgsLen))

    ev.DstAddr = ipv4FromRaw(readU32())
    ev.DstPort = readU16()
    _ = readU16()
    ev.TargetPid = readU32()

    ev.Family = readU8()
    ev.Protocol = readU8()
    ev.Direction = readU8()
    _ = readU8()

    ev.DstAddr6 = ipv6FromRaw(readBytes(16))
    ev.SrcAddr = ipv4FromRaw(readU32())
    ev.SrcAddr6 = ipv6FromRaw(readBytes(16))
    ev.SrcPort = readU16()
    _ = readU16()

    ev.OldUID = readU32()
    ev.NewUID = readU32()
    ev.SockFamily = readU32()
    ev.SockType = readU32()
    ev.PacketLen = readU32()

    if ev.Family != FamilyIPv4 {
        ev.DstAddr = nil
        ev.SrcAddr = nil
    }
    if ev.Family != FamilyIPv6 {
        ev.DstAddr6 = nil
        ev.SrcAddr6 = nil
    }

    return ev, nil
}
