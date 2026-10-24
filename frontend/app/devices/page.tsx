"use client";
import { apiFetch } from "@/lib/api";
import { useEffect, useState } from "react";
import { Activity } from "lucide-react";

type Device = {
  device_id: string; ip?: string; mac?: string; hostname?: string; vendor?: string;
  source?: string; last_network_seen?: string; last_agent_heartbeat?: string;
  last_endpoint_event?: string; agent_status?: string; network_status?: string;
  risk_level?: string; risk_assessed?: boolean;
};
const displayTime = (value?: string) => value
  ? new Date(value.endsWith("Z") ? value : value + "Z").toLocaleString() : "No observation";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [collection, setCollection] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      try {
        const [inventory, status] = await Promise.all([apiFetch("/devices/"), apiFetch("/discovery/status")]);
        const [rows, state] = await Promise.all([inventory.json(), status.json()]);
        if (!Array.isArray(rows)) throw new Error("Invalid inventory response");
        if (alive) { setDevices(rows); setCollection(state); setError(""); }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : "Inventory unavailable");
      } finally { if (alive) setLoading(false); }
    };
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, []);
  return <div className="space-y-6">
    <div className="flex flex-wrap justify-between gap-4">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3"><Activity />Device inventory</h1>
        <p className="text-muted-foreground mt-2">Stored observations from your approved network. Presence is not a security verdict.</p>
      </div>
      <div className="glass rounded-lg px-6 py-3">
        <strong className="text-3xl">{error ? "—" : collection?.observed_count ?? "—"}</strong>
        <span className="ml-2 text-sm">observed in last successful scan</span>
        <p className="text-xs text-muted-foreground mt-1">{devices.length} stored identities · includes this laptop and gateway</p>
      </div>
    </div>
    {error && <div role="alert" className="border border-red-500 rounded-lg p-4">Cannot refresh inventory: {error}. Previously displayed observations may be stale.</div>}
    <div className="glass rounded-lg p-4 text-sm text-muted-foreground">
      Names and MACs are shown only when available. Private MACs can change; identities may split.
      Sleeping or isolated devices may be missed. Compare with your router client list for completeness.
      Agent UNKNOWN means no verified heartbeat is stored.
    </div>
    {loading ? <p>Loading stored observations…</p> : !devices.length ?
      <div className="glass rounded-lg p-8"><h2 className="text-xl">No observations stored yet</h2>
        <p className="mt-2 text-muted-foreground">This does not mean the network is empty or safe. Start an explicitly approved local collection session.</p></div> :
      <div className="grid gap-4">{devices.map(device => <article key={device.device_id} className="glass rounded-lg p-5">
        <div className="flex flex-wrap justify-between gap-2">
          <h2 className="text-xl font-semibold">{device.hostname || "Name unavailable"}</h2>
          <span className="text-xs rounded bg-slate-800 px-3 py-2">{device.risk_assessed ? "Stored risk: " + device.risk_level : "Security: NOT ASSESSED"}</span>
        </div>
        <dl className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-sm">
          <div><dt className="text-muted-foreground">IP address</dt><dd>{device.ip || "Unavailable"}</dd></div>
          <div><dt className="text-muted-foreground">MAC address</dt><dd className="font-mono">{device.mac || "Unavailable"}</dd></div>
          <div><dt className="text-muted-foreground">MAC vendor (not device identity)</dt><dd>{device.vendor || "Unknown"}</dd></div>
          <div><dt className="text-muted-foreground">Network observation</dt><dd>{device.network_status || "UNKNOWN"}</dd><dd>{displayTime(device.last_network_seen)}</dd></div>
          <div><dt className="text-muted-foreground">Endpoint agent</dt><dd>{device.agent_status || "UNKNOWN"}</dd><dd>{displayTime(device.last_agent_heartbeat)}</dd></div>
          <div><dt className="text-muted-foreground">Last endpoint event</dt><dd>{displayTime(device.last_endpoint_event)}</dd><dd>Source: {device.source || "Unknown"}</dd></div>
        </dl>
      </article>)}</div>}
  </div>;
}
