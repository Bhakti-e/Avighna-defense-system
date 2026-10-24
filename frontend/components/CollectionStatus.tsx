"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

export default function CollectionStatus() {
  const [status, setStatus] = useState<any>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      try {
        const response = await apiFetch("/discovery/status");
        const data = await response.json();
        if (alive) { setStatus(data); setError(""); }
      } catch {
        if (alive) setError("API unavailable — collection status cannot be verified.");
      }
    };
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, []);
  const live = !error && status?.active && status?.last_scan;
  return <div role="status" className={"border-b px-4 py-3 text-sm " +
    (live ? "border-emerald-500/40 bg-emerald-950 text-emerald-100" : "border-amber-500/40 bg-amber-950 text-amber-100")}>
    <div className="flex flex-wrap justify-between gap-2">
      <strong>{error || (live ? "LIVE NETWORK DISCOVERY" : status?.active ? "DISCOVERY STARTING" :
        status ? "COLLECTION " + status.state.toUpperCase() : "Checking collection status…")}</strong>
      <a href="/devices" className="underline">View device inventory</a>
    </div>
    {!error && status?.scope && <p className="mt-1">
      Scope: {status.scope} · Last successful scan: {status.last_scan ? new Date(status.last_scan).toLocaleString() : "Not yet completed"}
      {status.observed_count != null && " · " + status.observed_count + " hosts observed"}
    </p>}
    {status?.error && <p className="mt-1">{status.error}</p>}
    <p className="mt-1 opacity-80">Network observations only. Endpoint protection, automatic containment and live threat-intelligence feeds are not enabled.</p>
  </div>;
}
