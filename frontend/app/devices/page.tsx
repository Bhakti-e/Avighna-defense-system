"use client";

import { useEffect, useState } from "react";
import { Activity, AlertCircle } from "lucide-react";
import { motion } from "framer-motion";

interface Device {
  device_id: string;
  name?: string;
  device_type?: string;
  ip?: string;
  mac?: string;
  vendor?: string;
  hostname?: string;
  last_seen?: string;
  last_risk?: number;
  risk_level?: string;
  status?: string;
  quarantined?: boolean;
}

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchDevices = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      const devicesRes = await fetch(`${API_URL}/devices/`);
      const devicesData = await devicesRes.json();
      setDevices(devicesData || []);
    } catch (error) {
      console.error("Failed to fetch devices:", error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level?: string) => {
    switch (level) {
      case "RED":
      case "CRITICAL":
        return "bg-destructive/20 text-destructive";
      case "YELLOW":
      case "HIGH":
        return "bg-warning/20 text-warning";
      case "GREEN":
      case "LOW":
        return "bg-success/20 text-success";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getDeviceIcon = (type?: string) => {
    switch (type) {
      case "router":
        return "🌐";
      case "phone":
        return "📱";
      case "laptop":
        return "💻";
      case "tablet":
        return "📱";
      case "iot":
        return "🔌";
      case "server":
        return "🖥️";
      default:
        return "❓";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-glow flex items-center space-x-3">
            <Activity className="w-8 h-8 text-success" />
            <span>Connected Devices</span>
          </h1>
          <p className="text-muted-foreground mt-2">
            Real-time network device monitoring
          </p>
        </div>
        <div className="glass px-6 py-3 rounded-lg">
          <span className="text-3xl font-bold">{devices.length}</span>
          <span className="text-sm text-muted-foreground ml-2">Total Active</span>
        </div>
      </div>

      {loading ? (
        <div className="glass rounded-lg p-12 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground mt-4">Loading devices...</p>
        </div>
      ) : devices.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <AlertCircle className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Devices Found</h3>
          <p className="text-muted-foreground">No active devices detected on network</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {devices.map((device, index) => (
            <motion.div
              key={device.device_id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="glass glass-hover rounded-lg p-6"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className="text-2xl">{getDeviceIcon(device.device_type)}</span>
                    <h3 className="text-lg font-semibold">{device.name || device.device_id}</h3>
                    {device.quarantined && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-destructive/20 text-destructive">
                        ISOLATED
                      </span>
                    )}
                    {device.risk_level && (
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(device.risk_level)}`}>
                        {device.risk_level}
                      </span>
                    )}
                    {device.device_type && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-primary/20 text-primary">
                        {device.device_type.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">IP:</span>
                      <span className="ml-2 font-medium">{device.ip || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">MAC:</span>
                      <span className="ml-2 font-mono text-xs">{device.mac || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Vendor:</span>
                      <span className="ml-2 font-medium">{device.vendor || "Unknown"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Status:</span>
                      <span className="ml-2 font-medium">{device.status || "Unknown"}</span>
                    </div>
                  </div>
                  {device.hostname && (
                    <div className="mt-2 text-sm">
                      <span className="text-muted-foreground">Hostname:</span>
                      <span className="ml-2 font-medium">{device.hostname}</span>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
