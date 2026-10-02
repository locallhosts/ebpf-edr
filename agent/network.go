package main

import (
    "sync"
    "time"
)

// NetworkFlow is the normalized network telemetry exposed to the dashboard/API.
// It intentionally contains metadata only; packet payloads are never captured.
type NetworkFlow struct {
    Time      time.Time `json:"time"`
    Pid       uint32 `json:"pid"`
    Ppid      uint32 `json:"ppid"`
    Comm      string `json:"comm"`
    EventType string `json:"event_type"`
    Family    string `json:"family"`
    Protocol  string `json:"protocol"`
    Direction string `json:"direction"`
    SrcAddr   string `json:"src_addr,omitempty"`
    SrcPort   uint16 `json:"src_port,omitempty"`
    DstAddr   string `json:"dst_addr,omitempty"`
    DstPort   uint16 `json:"dst_port,omitempty"`
}

type NetworkStore struct {
    mu    sync.Mutex
    cap   int
    flows []NetworkFlow
}

func NewNetworkStore(capacity int) *NetworkStore {
    return &NetworkStore{cap: capacity, flows: make([]NetworkFlow, 0, capacity)}
}

func (s *NetworkStore) Add(ev Event) {
    if !ev.NetworkEvent() && ev.Type != EvtSocketCreate {
        return
    }

    flow := NetworkFlow{
        Time: time.Now(), Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
        EventType: ev.TypeName(), Family: ev.FamilyName(),
        Protocol: ev.ProtocolName(), Direction: ev.DirectionName(),
        SrcAddr: ipString(ev.SrcAddr, ev.SrcAddr6), SrcPort: ev.SrcPort,
        DstAddr: ipString(ev.DstAddr, ev.DstAddr6), DstPort: ev.DstPort,
    }

    s.mu.Lock()
    defer s.mu.Unlock()
    if len(s.flows) >= s.cap {
        s.flows = s.flows[1:]
    }
    s.flows = append(s.flows, flow)
}

func (s *NetworkStore) Snapshot() []NetworkFlow {
    s.mu.Lock()
    defer s.mu.Unlock()
    cp := make([]NetworkFlow, len(s.flows))
    copy(cp, s.flows)
    return cp
}
