package main

import (
	"testing"
	"time"
)

func BenchmarkParseEvent(b *testing.B) {
	raw := make([]byte, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseEvent(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNetworkStoreAdd(b *testing.B) {
	s := NewNetworkStore(1000, 0)
	ev := Event{
		Pid: 123, Ppid: 1, Tgid: 123, Comm: "benchmark",
		Type: EvtPacket, Family: FamilyIPv4, Protocol: ProtocolTCP,
		Direction: DirectionOutbound, PacketLen: 128,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.SrcPort = uint16(10000 + i%1000)
		s.Add(ev, "")
	}
}

func BenchmarkNetworkStoreConcurrentAdd(b *testing.B) {
	s := NewNetworkStore(1000, time.Millisecond)
	ev := Event{
		Pid: 123, Ppid: 1, Tgid: 123, Comm: "benchmark",
		Type: EvtPacket, Family: FamilyIPv4, Protocol: ProtocolTCP,
		Direction: DirectionOutbound, PacketLen: 128,
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Add(ev, "")
		}
	})
}
