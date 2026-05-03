"use client";

import { useEffect, useState } from "react";
import { Bell, AlertTriangle } from "lucide-react";
import { motion } from "framer-motion";

interface Alert {
  id: string;
  device_id: string;
  reason: string;
  severity: number;
  action: string;
  timestamp: string;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${API_URL}/alerts/`);
      const data = await res.json();
      
      // Ensure data is an array
      if (Array.isArray(data)) {
        setAlerts(data);
      } else if (data && Array.isArray(data.alerts)) {
        setAlerts(data.alerts);
      } else {
        setAlerts([]);
      }
    } catch (error) {
      console.error("Failed to fetch alerts:", error);
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: number) => {
    if (severity >= 4) return "bg-destructive/20 text-destructive border-destructive";
    if (severity >= 3) return "bg-warning/20 text-warning border-warning";
    return "bg-primary/20 text-primary border-primary";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center space-x-3">
            <Bell className="w-8 h-8 text-destructive" />
            <span>Active Alerts</span>
          </h1>
          <p className="text-muted-foreground mt-2">
            Security notifications and events
          </p>
        </div>
        <div className="glass px-4 py-2 rounded-lg">
          <span className="text-2xl font-bold">{alerts.length}</span>
          <span className="text-sm text-muted-foreground ml-2">Alerts</span>
        </div>
      </div>

      {loading ? (
        <div className="glass rounded-lg p-12 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground mt-4">Loading alerts...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <Bell className="w-16 h-16 text-success mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Active Alerts</h3>
          <p className="text-muted-foreground">All systems operating normally</p>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.05 }}
              className={`glass rounded-lg p-6 border-l-4 ${getSeverityColor(alert.severity)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  <AlertTriangle className="w-5 h-5 mt-1" />
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold mb-1">{alert.reason}</h3>
                    <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                      <span>Device: {alert.device_id}</span>
                      <span>Action: {alert.action}</span>
                      <span>Severity: {alert.severity}/5</span>
                    </div>
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">
                  {new Date(alert.timestamp).toLocaleString()}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
