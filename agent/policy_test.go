package main

import (
	"net"
	"testing"
	"time"
)

func TestNetworkStoreDeduplicatesIdenticalRecords(t *testing.T) {
	s := NewNetworkStore(10, time.Second)
	ev := Event{
		Pid: 42, Ppid: 1, Tgid: 42, Comm: "curl",
		Type: EvtPacket, Family: FamilyIPv4, Protocol: ProtocolTCP,
		Direction: DirectionOutbound, SrcAddr: net.IPv4(127, 0, 0, 1),
		SrcPort: 40000, DstAddr: net.IPv4(10, 0, 0, 1), DstPort: 443,
		PacketLen: 120,
	}
	s.Add(ev, "")
	s.Add(ev, "")
	if got := len(s.Snapshot()); got != 1 {
		t.Fatalf("expected one flow after deduplication, got %d", got)
	}
}

func TestNetworkStoreKeepsDistinctDirections(t *testing.T) {
	s := NewNetworkStore(10, time.Second)
	ev := Event{
		Pid: 42, Ppid: 1, Tgid: 42, Comm: "curl",
		Type: EvtPacket, Family: FamilyIPv4, Protocol: ProtocolTCP,
		SrcAddr: net.IPv4(127, 0, 0, 1), SrcPort: 40000,
		DstAddr: net.IPv4(10, 0, 0, 1), DstPort: 443, PacketLen: 120,
	}
	ev.Direction = DirectionOutbound
	s.Add(ev, "")
	ev.Direction = DirectionInbound
	s.Add(ev, "")
	if got := len(s.Snapshot()); got != 2 {
		t.Fatalf("expected two directional flows, got %d", got)
	}
}

func TestPolicyEnvironmentParsing(t *testing.T) {
	t.Setenv("EDR_DISABLED_RULES", "rule-a, rule-b")
	t.Setenv("EDR_ALLOW_COMMS", "node, nginx")
	t.Setenv("EDR_ALLOW_EXECUTABLES", "/usr/bin/test")
	t.Setenv("EDR_NETWORK_DEDUP_WINDOW", "500ms")
	t.Setenv("EDR_CONTAINER_CONTEXT", "false")

	cfg := LoadConfig()
	if !cfg.DisabledRules["rule-a"] || !cfg.DisabledRules["rule-b"] {
		t.Fatal("disabled rules were not parsed")
	}
	if !cfg.AllowedComms["node"] || !cfg.AllowedComms["nginx"] {
		t.Fatal("allowed comms were not parsed")
	}
	if !cfg.AllowedExecutables["/usr/bin/test"] {
		t.Fatal("allowed executable was not parsed")
	}
	if cfg.NetworkDedupWindow != 500*time.Millisecond {
		t.Fatalf("unexpected dedup window: %s", cfg.NetworkDedupWindow)
	}
	if cfg.ContainerContext {
		t.Fatal("container context should be disabled")
	}
}

func TestContainerIDExtraction(t *testing.T) {
	if got := extractContainerID("docker-0123456789abcdef0123456789abcdef.scope"); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected docker id: %q", got)
	}
	if got := extractContainerID("0123456789abcdef0123456789abcdef"); got == "" {
		t.Fatal("expected bare hex container id")
	}
	if got := extractContainerID("user.slice"); got != "" {
		t.Fatalf("unexpected container id from %q", got)
	}
}
