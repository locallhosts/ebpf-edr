package main

import (
	"fmt"
	"sync"
	"time"
)

// NetworkFlow is the normalized network telemetry exposed to the dashboard/API.
// It intentionally contains metadata only; packet payloads are never captured.
type NetworkFlow struct {
	Time        time.Time `json:"time"`
	Pid         uint32    `json:"pid"`
	Ppid        uint32    `json:"ppid"`
	Comm        string    `json:"comm"`
	ContainerID string    `json:"container_id,omitempty"`
	EventType   string    `json:"event_type"`
	Family      string    `json:"family"`
	Protocol    string    `json:"protocol"`
	Direction   string    `json:"direction"`
	SrcAddr     string    `json:"src_addr,omitempty"`
	SrcPort     uint16    `json:"src_port,omitempty"`
	DstAddr     string    `json:"dst_addr,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
	PacketLen   uint32    `json:"packet_len,omitempty"`
}

type networkDedupKey struct {
	pid, ppid          uint32
	eventType          string
	family, protocol   string
	direction          string
	srcAddr, dstAddr   string
	srcPort, dstPort   uint16
	packetLen           uint32
}

type NetworkStore struct {
	mu        sync.Mutex
	cap       int
	flows     []NetworkFlow
	dedup     map[networkDedupKey]time.Time
	dedupWindow time.Duration
}

func NewNetworkStore(capacity int, dedupWindow time.Duration) *NetworkStore {
	if dedupWindow < 0 {
		dedupWindow = 0
	}
	return &NetworkStore{
		cap: capacity,
		flows: make([]NetworkFlow, 0, capacity),
		dedup: make(map[networkDedupKey]time.Time),
		dedupWindow: dedupWindow,
	}
}

func (s *NetworkStore) Add(ev Event, containerID string) {
	if !ev.NetworkEvent() && ev.Type != EvtSocketCreate {
		return
	}

	now := time.Now()
	flow := NetworkFlow{
		Time: now, Pid: ev.Pid, Ppid: ev.Ppid, Comm: ev.Comm,
		ContainerID: containerID,
		EventType: ev.TypeName(), Family: ev.FamilyName(),
		Protocol: ev.ProtocolName(), Direction: ev.DirectionName(),
		SrcAddr: ipString(ev.SrcAddr, ev.SrcAddr6), SrcPort: ev.SrcPort,
		DstAddr: ipString(ev.DstAddr, ev.DstAddr6), DstPort: ev.DstPort,
		PacketLen: ev.PacketLen,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := networkDedupKey{
		pid: flow.Pid, ppid: flow.Ppid, eventType: flow.EventType,
		family: flow.Family, protocol: flow.Protocol, direction: flow.Direction,
		srcAddr: flow.SrcAddr, srcPort: flow.SrcPort,
		dstAddr: flow.DstAddr, dstPort: flow.DstPort, packetLen: flow.PacketLen,
	}
	if s.dedupWindow > 0 {
		if last, ok := s.dedup[key]; ok && now.Sub(last) <= s.dedupWindow {
			networkDeduped.Inc()
			return
		}
		s.dedup[key] = now
		if len(s.dedup) > s.cap*2 {
			cutoff := now.Add(-s.dedupWindow)
			for k, t := range s.dedup {
				if t.Before(cutoff) {
					delete(s.dedup, k)
				}
			}
		}
	}

	if len(s.flows) >= s.cap && s.cap > 0 {
		s.flows = s.flows[1:]
	}
	if s.cap > 0 {
		s.flows = append(s.flows, flow)
	}
}

func (s *NetworkStore) Snapshot() []NetworkFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]NetworkFlow, len(s.flows))
	copy(cp, s.flows)
	return cp
}

func (s NetworkFlow) String() string {
	return fmt.Sprintf("%s %s/%s %s %s:%d -> %s:%d", s.EventType, s.Family, s.Protocol, s.Direction, s.SrcAddr, s.SrcPort, s.DstAddr, s.DstPort)
}
