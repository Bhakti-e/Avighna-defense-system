"use client";

import { useEffect, useState } from "react";
import { Shield, Download, AlertTriangle } from "lucide-react";
import { motion } from "framer-motion";

interface IsolatedDevice {
  device_id: string;
  status: string;
  quarantine_time: number;
  last_risk: number;
  risk_level: string;
  isolation_time_readable: string;
  isolation_details: {
    download_url?: string;
    forensics_path?: string;
    isolation_reason?: string;
  };
}

export default function IsolationPage() {
  const [devices, setDevices] = useState<IsolatedDevice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIsolatedDevices();
    const interval = setInterval(fetchIsolatedDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchIsolatedDevices = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      const res = await fetch(`${API_URL}/reports/isolation/details`);
      const data = await res.json();
      setDevices(data.isolated_devices || []);
    } catch (error) {
      console.error("Failed to fetch isolated devices:", error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "CRITICAL":
      case "RED":
        return "text-destructive";
      case "HIGH":
        return "text-warning";
      default:
        return "text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-glow flex items-center space-x-3">
            <Shield className="w-8 h-8 text-destructive" />
            <span>Isolated Devices</span>
          </h1>
          <p className="text-muted-foreground mt-2">
            Quarantined threats and forensic reports
          </p>
        </div>
        <div className="glass px-4 py-2 rounded-lg">
          <span className="text-2xl font-bold">{devices.length}</span>
          <span className="text-sm text-muted-foreground ml-2">Isolated</span>
        </div>
      </div>

      {loading ? (
        <div className="glass rounded-lg p-12 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground mt-4">Loading isolated devices...</p>
        </div>
      ) : devices.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <Shield className="w-16 h-16 text-success mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Isolated Devices</h3>
          <p className="text-muted-foreground">All devices are operating normally</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {devices.map((device, index) => (
            <motion.div
              key={device.device_id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="glass glass-hover rounded-lg p-6 shadow-glow-red"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-3">
                    <AlertTriangle className="w-5 h-5 text-destructive" />
                    <h3 className="text-lg font-semibold">{device.device_id}</h3>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(device.risk_level)}`}>
                      {device.risk_level}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Status:</span>
                      <span className="ml-2 font-medium">{device.status}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Risk Score:</span>
                      <span className="ml-2 font-medium">{device.last_risk}/100</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Isolated:</span>
                      <span className="ml-2 font-medium">{device.isolation_time_readable}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Reason:</span>
                      <span className="ml-2 font-medium">
                        {device.isolation_details?.isolation_reason || "Critical threat detected"}
                      </span>
                    </div>
                  </div>
                </div>

                {device.isolation_details?.download_url && (
                  <a
                    href={device.isolation_details.download_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-4 px-4 py-2 bg-primary hover:bg-primary/80 rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span className="text-sm font-medium">Download PDF</span>
                  </a>
                )}
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
