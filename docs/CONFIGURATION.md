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
