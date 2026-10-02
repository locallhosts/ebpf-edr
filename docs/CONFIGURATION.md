# Agent Configuration

The agent keeps policy in userspace and reads configuration from environment variables. This keeps deployment portable and avoids adding a configuration-file dependency.

## Detection policy

Disable specific rules:

```bash
export EDR_DISABLED_RULES="unexpected-ptrace,raw-or-packet-socket"
```

Allow known-good process names:

```bash
export EDR_ALLOW_COMMS="node,nginx,systemd"
```

Allow known-good executable paths:

```bash
export EDR_ALLOW_EXECUTABLES="/usr/bin/gdb,/usr/local/bin/my-security-tool"
```

An allowed process name or executable suppresses detections generated for that event. Use narrow allowlists; a process name alone is not a strong identity boundary.

## Network deduplication

The userspace network store suppresses identical metadata records observed within a short window.

```bash
export EDR_NETWORK_DEDUP_WINDOW="250ms"
```

Set it to `0` to disable deduplication.

## Container context

The agent can enrich network telemetry with a best-effort container/cgroup identifier from `/proc/<pid>/cgroup`.

```bash
export EDR_CONTAINER_CONTEXT="true"
```

This is intentionally best-effort. The agent does not require container metadata to process an event.

## SIEM/SOAR webhook

Security alerts can be sent as JSON POST requests to a generic webhook endpoint:

```bash
export EDR_WEBHOOK_URL="https://siem.example/api/ingest"
export EDR_WEBHOOK_TOKEN="replace-with-secret"
```

The webhook is asynchronous and bounded to 256 queued alerts. If the queue is full, alerts are counted as dropped rather than blocking the kernel event-processing loop.

Metrics:

- `edr_webhook_delivered_total`
- `edr_webhook_failures_total`
- `edr_webhook_dropped_total`
- `edr_network_events_deduped_total`
- `edr_ringbuf_lost_total`

The webhook integration is vendor-neutral. A SIEM/SOAR adapter can transform the JSON alert into the destination's native event schema without coupling the agent to a specific platform.


## XDP / Layer-2 telemetry

XDP ingress telemetry is opt-in because it attaches directly to a network interface:

    export EDR_XDP_INTERFACE="eth0"
    sudo ./bin/edr-agent

The XDP program runs in generic XDP mode and returns XDP_PASS, so it is a visibility sensor rather than a packet-dropping firewall. It parses Ethernet, one VLAN tag, IPv4, and IPv6 metadata. IPv6 extension headers are walked with a bounded parser.

XDP events use PID/TGID 0 because the XDP hook executes before normal process context is available. They are therefore network observations, not process-attributed events.

## Ring-buffer loss validation

The kernel increments edr_ringbuf_lost_total whenever an event cannot be reserved from the main ring buffer. This is an actual kernel-side drop counter, not an estimate from userspace.

Run the validation suite on a Linux host with root/BPF privileges:

    sudo make test-validation

For an end-to-end overload test, run the agent with a deliberately slowed reader in a controlled lab environment, generate a high rate of short-lived syscalls, and verify that /metrics reports a non-zero edr_ringbuf_lost_total. This is intentionally a lab validation because overload reduces telemetry fidelity.
