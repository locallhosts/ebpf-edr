import { useMemo, useState } from "react";
import { useAlerts } from "./useAlerts";
import { severityColor, severityRank, type Alert } from "./types";

const AGENT_URL = import.meta.env.VITE_AGENT_URL ?? "";

// MITRE ATT&CK technique names for the IDs this agent's rule set can
// emit (agent/detect.go). Kept local rather than pulling the full
// ATT&CK STIX bundle to keep this dashboard dependency-free — extend
// this map if you add rules that map to new techniques.
const TECHNIQUE_NAMES: Record<string, string> = {
  "T1059": "Command and Scripting Interpreter",
  "T1059.004": "Command and Scripting Interpreter: Unix Shell",
  "T1036.005": "Masquerading: Match Legitimate Name or Location",
  "T1552": "Unsecured Credentials",
  "T1055": "Process Injection",
};

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diffMs / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

function SeverityBadge({ severity }: { severity: Alert["severity"] }) {
  return (
    <span
      style={{
        background: severityColor[severity],
        color: "#0a0a0a",
        fontWeight: 700,
        fontSize: 11,
        padding: "2px 8px",
        borderRadius: 999,
        letterSpacing: 0.4,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </span>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <tr style={{ borderBottom: "1px solid #262626" }}>
      <td style={{ padding: "10px 12px", whiteSpace: "nowrap", color: "#a3a3a3", fontSize: 13 }}>
        {relativeTime(alert.time)}
      </td>
      <td style={{ padding: "10px 12px" }}>
        <SeverityBadge severity={alert.severity} />
      </td>
      <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 13, color: "#e5e5e5" }}>
        {alert.rule}
      </td>
      <td style={{ padding: "10px 12px", fontSize: 13 }}>
        <span title={TECHNIQUE_NAMES[alert.mitre_technique] ?? ""} style={{ color: "#60a5fa" }}>
          {alert.mitre_technique}
        </span>
      </td>
      <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 13, color: "#e5e5e5" }}>
        {alert.comm} <span style={{ color: "#737373" }}>(pid {alert.pid})</span>
      </td>
      <td style={{ padding: "10px 12px", fontSize: 13, color: "#d4d4d4", maxWidth: 480 }}>
        {alert.description}
      </td>
    </tr>
  );
}

export default function App() {
  const { alerts, connected, lastError } = useAlerts(AGENT_URL);
  const [minSeverity, setMinSeverity] = useState<Alert["severity"]>("Low");

  const filtered = useMemo(
    () =>
      [...alerts]
        .filter((a) => severityRank[a.severity] >= severityRank[minSeverity])
        .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()),
    [alerts, minSeverity]
  );

  const techniqueCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of alerts) counts.set(a.mitre_technique, (counts.get(a.mitre_technique) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [alerts]);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", background: "#0a0a0a", minHeight: "100vh", color: "#fafafa" }}>
      <header style={{ padding: "20px 28px", borderBottom: "1px solid #262626", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>eBPF EDR — Live Alert Console</h1>
          <p style={{ margin: "4px 0 0", color: "#737373", fontSize: 13 }}>
            Kernel-level detection agent · {alerts.length} alerts in buffer
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
          <span
            style={{
              width: 8, height: 8, borderRadius: "50%",
              background: connected ? "#22c55e" : "#ef4444",
              display: "inline-block",
            }}
          />
          {connected ? "agent connected" : `agent unreachable${lastError ? `: ${lastError}` : ""}`}
        </div>
      </header>

      <main style={{ padding: 28, display: "grid", gridTemplateColumns: "1fr 320px", gap: 24 }}>
        <section>
          <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center" }}>
            <span style={{ fontSize: 13, color: "#a3a3a3" }}>Min severity:</span>
            {(["Low", "Medium", "High", "Critical"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setMinSeverity(s)}
                style={{
                  background: minSeverity === s ? severityColor[s] : "transparent",
                  color: minSeverity === s ? "#0a0a0a" : "#a3a3a3",
                  border: `1px solid ${minSeverity === s ? severityColor[s] : "#404040"}`,
                  borderRadius: 6,
                  padding: "4px 10px",
                  fontSize: 12,
                  cursor: "pointer",
                  fontWeight: 600,
                }}
              >
                {s}
              </button>
            ))}
          </div>

          <div style={{ border: "1px solid #262626", borderRadius: 10, overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#171717", textAlign: "left" }}>
                  {["When", "Severity", "Rule", "Technique", "Process", "Description"].map((h) => (
                    <th key={h} style={{ padding: "10px 12px", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: "#737373" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: 24, textAlign: "center", color: "#525252" }}>
                      No alerts at this severity yet — waiting on kernel telemetry...
                    </td>
                  </tr>
                ) : (
                  filtered.map((a, i) => <AlertRow key={`${a.time}-${a.pid}-${i}`} alert={a} />)
                )}
              </tbody>
            </table>
          </div>
        </section>

        <aside>
          <h2 style={{ fontSize: 14, textTransform: "uppercase", letterSpacing: 0.5, color: "#737373", marginBottom: 12 }}>
            MITRE ATT&CK Coverage
          </h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {techniqueCounts.length === 0 && <p style={{ color: "#525252", fontSize: 13 }}>No detections yet.</p>}
            {techniqueCounts.map(([tech, count]) => (
              <div key={tech} style={{ border: "1px solid #262626", borderRadius: 8, padding: "10px 12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                  <span style={{ color: "#60a5fa", fontFamily: "monospace" }}>{tech}</span>
                  <span style={{ color: "#a3a3a3" }}>{count}×</span>
                </div>
                <div style={{ fontSize: 12, color: "#737373", marginTop: 2 }}>
                  {TECHNIQUE_NAMES[tech] ?? "Unknown technique"}
                </div>
              </div>
            ))}
          </div>
        </aside>
      </main>
    </div>
  );
}
