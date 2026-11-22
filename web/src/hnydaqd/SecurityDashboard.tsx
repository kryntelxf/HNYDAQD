"use client";

import { useEffect, useState } from "react";

interface AuditSummary {
  total_events: number;
  integrity_ok: boolean;
}

interface Classification {
  level: string;
  rank: number;
}

interface Provider {
  provider: string;
  max_classification: string;
}

interface SecurityStatus {
  audit: AuditSummary;
  classifications: Classification[];
  providers: Provider[];
}

export default function SecurityDashboard() {
  const [data, setData] = useState<SecurityStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/hnydaqd/status")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <div style={{ padding: 24 }}>Error: {error}</div>;
  if (!data) return <div style={{ padding: 24 }}>Loading security status...</div>;

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>HNYDAQD Security Dashboard</h1>

      <section>
        <h2>Audit Chain</h2>
        <p>Total Events: {data.audit.total_events}</p>
        <p>
          Integrity:{" "}
          <strong style={{ color: data.audit.integrity_ok ? "green" : "red" }}>
            {data.audit.integrity_ok ? "OK" : "COMPROMISED"}
          </strong>
        </p>
      </section>

      <section>
        <h2>Classification Levels</h2>
        <ul>
          {data.classifications.map((c) => (
            <li key={c.level}>
              {c.level} (rank {c.rank})
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Provider Routing</h2>
        <ul>
          {data.providers.map((p) => (
            <li key={p.provider}>
              {p.provider} → up to {p.max_classification}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
