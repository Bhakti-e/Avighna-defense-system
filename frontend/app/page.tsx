"use client";
import { apiFetch } from "@/lib/api";

import { useEffect, useState } from "react";
import DashboardCard from "@/components/DashboardCard";
import { Shield, AlertTriangle, Eye, Activity, Bell, Target, Terminal } from "lucide-react";

interface Stats {
  devices: number;
  alerts: number;
  isolated: number;
  observed: number;
  recon: number;
  threatScore?: number;
  status?: string;
}

interface ThreatIntel {
  title: string;
  source: string;
  severity: string;
  timestamp: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    devices: 0,
    alerts: 0,
    isolated: 0,
    observed: 0,
    recon: 0,
  });
  
  const [threatIntel, setThreatIntel] = useState<ThreatIntel[]>([]);

  useEffect(() => {
    fetchStats();
    fetchThreatIntel();
    const interval = setInterval(() => {
      fetchStats();
      fetchThreatIntel();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    
    try {
      const res = await apiFetch(`${API_URL}/stats/dashboard`);
      const data = await res.json();

      setStats({
        devices: data.devices?.total || 0,
        alerts: data.alerts?.recent || 0,
        isolated: data.devices?.isolated || 0,
        observed: data.devices?.observed || 0,
        recon: data.reconnaissance?.events || 0,
        threatScore: data.threat_score || 0,
        status: data.status || "normal",
      });
    } catch (error) {
      console.error("Failed to fetch stats:", error);
    }
  };

  const fetchThreatIntel = async () => {
    setThreatIntel([]); // No live feed connected; never fabricate intelligence.
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Defense Dashboard</h1>
        <p className="text-muted-foreground mt-2">
          Network visibility prototype. Threat detection and response remain under validation.
        </p>
      </div>

      {/* Dashboard Cards with Glows */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <DashboardCard
          title="Stored Devices"
          count={stats.devices}
          icon={<Activity className="w-6 h-6" />}
          color="green"
          href="/devices"
          description="Open inventory for observed hosts and timestamps"
          glow="green"
        />

        <DashboardCard
          title="Reconnaissance"
          count={stats.recon}
          icon={<Activity className="w-6 h-6" />}
          color="red"
          href="/recon"
          description="Active network scanning events"
          glow="red"
        />

        <DashboardCard
          title="Under Observation"
          count={stats.observed}
          icon={<Eye className="w-6 h-6" />}
          color="yellow"
          href="/observation"
          description="Monitored suspicious activity"
          glow="yellow"
        />

        <DashboardCard
          title="Isolated Devices"
          count={stats.isolated}
          icon={<Shield className="w-6 h-6" />}
          color="red"
          href="/isolation"
          description="Quarantined threats"
          glow="orange"
        />

        <DashboardCard
          title="Active Alerts"
          count={stats.alerts}
          icon={<Bell className="w-6 h-6" />}
          color="red"
          href="/alerts"
          description="Security notifications"
          glow="red-pulse"
        />

        {/* FOX Threat Intelligence Preview */}
        <div 
          onClick={() => window.location.href = "/threat-intelligence"}
          className="glass rounded-lg p-6 cursor-pointer hover:border-primary/50 transition-all relative overflow-hidden group"
          style={{
            boxShadow: "0 0 15px rgba(59, 130, 246, 0.15)"
          }}
        >
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
          <div className="relative">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <p className="text-sm text-muted-foreground mb-2">Threat intelligence (not connected)</p>
                <div className="flex items-center space-x-2">
                  <Target className="w-5 h-5 text-blue-500" />
                  <h2 className="text-2xl font-bold">{threatIntel.length}</h2>
                </div>
              </div>
            </div>
            <div className="space-y-2">
              {threatIntel.slice(0, 2).map((intel, idx) => (
                <div key={idx} className="text-xs">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${
                    intel.severity === "CRITICAL" ? "bg-red-500/20 text-red-500" :
                    intel.severity === "HIGH" ? "bg-orange-500/20 text-orange-500" :
                    "bg-yellow-500/20 text-yellow-500"
                  }`}>
                    {intel.severity}
                  </span>
                  <p className="mt-1 text-muted-foreground truncate">{intel.title}</p>
                </div>
              ))}
            </div>
            <p className="text-xs text-blue-500 mt-3">View preview limitations →</p>
          </div>
        </div>
      </div>

      <section id="investigation-console" className="glass rounded-lg p-6">
        <h2 className="text-xl font-semibold">Diagnostics disabled</h2>
        <p className="mt-2 text-muted-foreground">
          Remote command execution is unavailable in this prototype. No shell or network command will run here.
        </p>
      </section>
    </div>
  );
}
