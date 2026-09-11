// Mirrors agent/detect.go `Alert` struct field-for-field (JSON tags
// must match). If you add a field on the Go side, add it here too —
// there is no shared schema file, so this is the contract.
export interface Alert {
  time: string; // RFC3339, from Go's time.Time JSON marshaling
  severity: "Low" | "Medium" | "High" | "Critical";
  mitre_technique: string;
  rule: string;
  pid: number;
  ppid: number;
  comm: string;
  description: string;
}

export const severityRank: Record<Alert["severity"], number> = {
  Low: 0,
  Medium: 1,
  High: 2,
  Critical: 3,
};

export const severityColor: Record<Alert["severity"], string> = {
  Low: "#3b82f6",
  Medium: "#eab308",
  High: "#f97316",
  Critical: "#ef4444",
};
