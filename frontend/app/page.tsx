"use client";

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
  const [command, setCommand] = useState("");
  const [commandOutput, setCommandOutput] = useState<string[]>([]);
  const [commandRunning, setCommandRunning] = useState(false);

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
    const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    
    try {
      const res = await fetch(`${API_URL}/stats/dashboard`);
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
    // Mock threat intelligence data
    // In production, this would fetch from real CTI feeds
    setThreatIntel([
      {
        title: "CVE-2024-1234: Critical RCE in Apache",
        source: "CISA",
        severity: "CRITICAL",
        timestamp: new Date().toISOString()
      },
      {
        title: "Ransomware campaign targeting SMBs",
        source: "Cisco Talos",
        severity: "HIGH",
        timestamp: new Date().toISOString()
      },
      {
        title: "New botnet activity detected",
        source: "AlienVault OTX",
        severity: "MEDIUM",
        timestamp: new Date().toISOString()
      }
    ]);
  };

  const allowedCommands = ["ping", "tracert", "nslookup", "nmap", "arp", "netstat"];

  const runCommand = async () => {
    const cmd = command.trim();
    if (!cmd) return;

    const cmdName = cmd.split(" ")[0].toLowerCase();
    
    if (!allowedCommands.includes(cmdName)) {
      setCommandOutput(prev => [
        ...prev,
        `$ ${cmd}`,
        `ERROR: Command '${cmdName}' is not allowed.`,
        `Allowed commands: ${allowedCommands.join(", ")}`,
        ""
      ]);
      setCommand("");
      return;
    }

    setCommandRunning(true);
    setCommandOutput(prev => [...prev, `$ ${cmd}`, "Running command..."]);

    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await fetch(`${API_URL}/investigation/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd })
      });

      if (response.ok) {
        const data = await response.json();
        setCommandOutput(prev => [
          ...prev.slice(0, -1),
          data.output || "Command completed successfully",
          ""
        ]);
      } else {
        setCommandOutput(prev => [
          ...prev.slice(0, -1),
          "ERROR: Command execution failed",
          ""
        ]);
      }
    } catch (error) {
      setCommandOutput(prev => [
        ...prev.slice(0, -1),
        "ERROR: Failed to execute command. Backend endpoint not available.",
        ""
      ]);
    } finally {
      setCommandRunning(false);
      setCommand("");
    }
  };

  // Function to auto-fill command with device IP
  const autoFillCommand = (ip: string, cmd: string = "nmap") => {
    setCommand(`${cmd} ${ip}`);
    // Scroll to investigation console
    setTimeout(() => {
      document.getElementById("investigation-console")?.scrollIntoView({ behavior: "smooth" });
    }, 100);
  };

  // Expose autoFillCommand globally for other components
  useEffect(() => {
    (window as any).autoFillInvestigation = autoFillCommand;
    return () => {
      delete (window as any).autoFillInvestigation;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Defense Dashboard</h1>
        <p className="text-muted-foreground mt-2">
          Real-time network threat monitoring and response
        </p>
      </div>

      {/* Dashboard Cards with Glows */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <DashboardCard
          title="Live Devices"
          count={stats.devices}
          icon={<Activity className="w-6 h-6" />}
          color="green"
          href="/devices"
          description="Active network devices"
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
                <p className="text-sm text-muted-foreground mb-2">FOX Intel</p>
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
            <p className="text-xs text-blue-500 mt-3">View all threats →</p>
          </div>
        </div>
      </div>

      {/* Investigation Console */}
      <div id="investigation-console" className="glass rounded-lg p-6">
        <div className="flex items-center space-x-3 mb-6">
          <Terminal className="w-7 h-7 text-primary" />
          <div>
            <h2 className="text-2xl font-semibold">Investigation Console</h2>
            <p className="text-sm text-muted-foreground mt-1">
              Controlled security investigation tools
            </p>
          </div>
        </div>

        {/* Command Input */}
        <div className="flex space-x-2 mb-4">
          <input
            type="text"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyPress={(e) => e.key === "Enter" && !commandRunning && runCommand()}
            placeholder="Enter command (ping, tracert, nslookup, nmap, arp, netstat)"
            className="flex-1 px-5 py-3 bg-background/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
            disabled={commandRunning}
          />
          <button
            onClick={runCommand}
            disabled={commandRunning || !command.trim()}
            className="px-8 py-3 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
          >
            {commandRunning ? "Running..." : "Run"}
          </button>
        </div>

        {/* Command Output */}
        <div className="bg-black/50 rounded-lg p-5 font-mono text-sm min-h-[200px] max-h-[400px] overflow-y-auto leading-relaxed">
          {commandOutput.length === 0 ? (
            <div className="text-muted-foreground">
              <p className="text-green-400">$ Investigation Console Ready</p>
              <p className="mt-3">Allowed commands:</p>
              <ul className="ml-4 mt-2 space-y-1">
                {allowedCommands.map(cmd => (
                  <li key={cmd}>• {cmd}</li>
                ))}
              </ul>
            </div>
          ) : (
            commandOutput.map((line, idx) => (
              <div key={idx} className={line.startsWith("$") ? "text-green-400 font-semibold" : line.startsWith("ERROR") ? "text-red-400" : "text-gray-300"}>
                {line}
              </div>
            ))
          )}
        </div>

        <div className="mt-4 text-xs text-muted-foreground">
          <p>⚠️ Only whitelisted security investigation commands are allowed</p>
        </div>
      </div>
    </div>
  );
}
