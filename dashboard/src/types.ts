// Mirrors agent/detect.go Alert JSON contract.
export interface Alert {
  time: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  mitre_technique: string;
  rule: string;
  pid: number;
  ppid: number;
  comm: string;
  description: string;

  protocol?: string;
  family?: string;
  direction?: "INBOUND" | "OUTBOUND";
  src_addr?: string;
  src_port?: number;
  dst_addr?: string;
  dst_port?: number;
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


export interface NetworkFlow {
  time: string;
  pid: number;
  ppid: number;
  comm: string;
  event_type: "CONNECT" | "ACCEPT" | "LISTEN" | "SOCKET" | "PACKET";
  family: string;
  protocol: string;
  direction: "INBOUND" | "OUTBOUND";
  src_addr?: string;
  src_port?: number;
  dst_addr?: string;
  dst_port?: number;
  packet_len?: number;
}
