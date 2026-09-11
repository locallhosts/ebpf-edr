import { useEffect, useRef, useState } from "react";
import type { Alert } from "./types";

interface UseAlertsResult {
  alerts: Alert[];
  connected: boolean;
  lastError: string | null;
}

// useAlerts polls the agent's /api/alerts endpoint on a fixed interval.
// A real production dashboard would prefer a server-sent-events or
// websocket push from the agent to avoid polling latency, but polling
// keeps the agent's HTTP surface tiny (one handler, no connection
// bookkeeping) which is the right tradeoff for a lab/demo tool — call
// this out explicitly if you extend this for a real deployment.
export function useAlerts(agentBaseUrl: string, pollMs = 2000): UseAlertsResult {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const timerRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const res = await fetch(`${agentBaseUrl}/api/alerts`);
        if (!res.ok) throw new Error(`agent returned HTTP ${res.status}`);
        const data: Alert[] = await res.json();
        if (!cancelled) {
          setAlerts(data);
          setConnected(true);
          setLastError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setConnected(false);
          setLastError(err instanceof Error ? err.message : String(err));
        }
      }
    }

    poll();
    timerRef.current = window.setInterval(poll, pollMs);
    return () => {
      cancelled = true;
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, [agentBaseUrl, pollMs]);

  return { alerts, connected, lastError };
}
