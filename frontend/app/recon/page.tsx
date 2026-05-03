"use client";

import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Shield } from "lucide-react";
import { motion } from "framer-motion";

interface Alert {
  type: string;
  severity: string;
  ip?: string;
  mac?: string;
  macs?: string[];
  ips?: string[];
  timestamp: number;
  description: string;
  vendor?: string;
  count?: number;
}

export default function ReconPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<any>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReconData();
    const interval = setInterval(fetchReconData, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchReconData = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      
      const [alertsRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/network/alerts`),
        fetch(`${API_URL}/network/stats`),
      ]);
      
      const alertsData = await alertsRes.json();
      const statsData = await statsRes.json();
      
      setAlerts(alertsData.alerts || []);
      setStats(statsData.stats || {});
    } catch (error) {
      console.error("Failed to fetch recon data:", error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-destructive/20 text-destructive border-destructive";
      case "HIGH":
        return "bg-warning/20 text-warning border-warning";
      case "MEDIUM":
        return "bg-warning/10 text-warning border-warning/50";
      default:
        return "bg-muted text-muted-foreground border-border";
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "arp_spoof":
        return <AlertTriangle className="w-5 h-5" />;
      case "mac_spoof":
        return <Shield className="w-5 h-5" />;
      case "probe_flood":
        return <Activity className="w-5 h-5" />;
      default:
        return <Activity className="w-5 h-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-glow flex items-center space-x-3">
            <Activity className="w-8 h-8 text-primary" />
            <span>Reconnaissance Events</span>
          </h1>
          <p className="text-muted-foreground mt-2">
            Real-time attack detection and network scanning
          </p>
        </div>
        <div className="glass px-4 py-2 rounded-lg">
          <span className="text-2xl font-bold">{alerts.length}</span>
          <span className="text-sm text-muted-foreground ml-2">Active Alerts</span>
        </div>
      </div>

      {/* Stats Cards */}
      {stats.packets_processed && (
        <div className="grid grid-cols-4 gap-4">
          <div className="glass rounded-lg p-4">
            <p className="text-sm text-muted-foreground mb-1">Packets Processed</p>
            <p className="text-2xl font-bold">{stats.packets_processed?.toLocaleString()}</p>
          </div>
          <div className="glass rounded-lg p-4">
            <p className="text-sm text-muted-foreground mb-1">Devices Discovered</p>
            <p className="text-2xl font-bold">{stats.devices_discovered}</p>
          </div>
          <div className="glass rounded-lg p-4">
            <p className="text-sm text-muted-foreground mb-1">Attacks Detected</p>
            <p className="text-2xl font-bold text-destructive">{stats.attacks_detected}</p>
          </div>
          <div className="glass rounded-lg p-4">
            <p className="text-sm text-muted-foreground mb-1">Uptime</p>
            <p className="text-2xl font-bold">
              {stats.uptime_seconds ? Math.floor(stats.uptime_seconds / 60) : 0}m
            </p>
          </div>
        </div>
      )}

      {/* Alerts List */}
      {loading ? (
        <div className="glass rounded-lg p-12 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground mt-4">Loading reconnaissance data...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <Shield className="w-16 h-16 text-success mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Active Threats</h3>
          <p className="text-muted-foreground">Network is secure - no reconnaissance detected</p>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alert, index) => (
            <motion.div
              key={`${alert.type}-${alert.timestamp}-${index}`}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`glass rounded-lg p-6 border-l-4 ${getSeverityColor(alert.severity)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  <div className={`p-3 rounded-lg ${getSeverityColor(alert.severity)}`}>
                    {getTypeIcon(alert.type)}
                  </div>
                  
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold capitalize">
                        {alert.type.replace(/_/g, " ")}
                      </h3>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                    
                    <p className="text-sm text-muted-foreground mb-3">{alert.description}</p>
                    
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      {alert.ip && (
                        <div>
                          <span className="text-muted-foreground">IP:</span>
                          <span className="ml-2 font-medium">{alert.ip}</span>
                        </div>
                      )}
                      {alert.mac && (
                        <div>
                          <span className="text-muted-foreground">MAC:</span>
                          <span className="ml-2 font-mono text-xs">{alert.mac}</span>
                        </div>
                      )}
                      {alert.vendor && (
                        <div>
                          <span className="text-muted-foreground">Vendor:</span>
                          <span className="ml-2 font-medium">{alert.vendor}</span>
                        </div>
                      )}
                      {alert.macs && (
                        <div className="col-span-2">
                          <span className="text-muted-foreground">Conflicting MACs:</span>
                          <div className="mt-1 flex flex-wrap gap-2">
                            {alert.macs.map((mac) => (
                              <span key={mac} className="px-2 py-1 bg-card rounded text-xs font-mono">
                                {mac}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {alert.ips && (
                        <div className="col-span-2">
                          <span className="text-muted-foreground">Claimed IPs:</span>
                          <div className="mt-1 flex flex-wrap gap-2">
                            {alert.ips.slice(0, 10).map((ip) => (
                              <span key={ip} className="px-2 py-1 bg-card rounded text-xs">
                                {ip}
                              </span>
                            ))}
                            {alert.ips.length > 10 && (
                              <span className="px-2 py-1 bg-card rounded text-xs">
                                +{alert.ips.length - 10} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="text-right text-sm text-muted-foreground">
                  {new Date(alert.timestamp * 1000).toLocaleString()}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
