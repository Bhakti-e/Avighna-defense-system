"use client";

import { useEffect, useState } from "react";
import { Eye, Clock } from "lucide-react";
import { motion } from "framer-motion";

interface ObservedDevice {
  device_id: string;
  status: string;
  observation_start: number;
  observation_reason: string;
  limit_kbps: number;
  allowed_outbound: string[];
  last_risk: number;
}

export default function ObservationPage() {
  const [devices, setDevices] = useState<ObservedDevice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchObservedDevices();
    const interval = setInterval(fetchObservedDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchObservedDevices = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      const res = await fetch(`${API_URL}/reports/observation/details`);
      const data = await res.json();
      setDevices(data.observed_devices || []);
    } catch (error) {
      console.error("Failed to fetch observed devices:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-glow flex items-center space-x-3">
            <Eye className="w-8 h-8 text-warning" />
            <span>Under Observation</span>
          </h1>
          <p className="text-muted-foreground mt-2">
            Monitored devices with restricted access
          </p>
        </div>
        <div className="glass px-4 py-2 rounded-lg">
          <span className="text-2xl font-bold">{devices.length}</span>
          <span className="text-sm text-muted-foreground ml-2">Monitored</span>
        </div>
      </div>

      {loading ? (
        <div className="glass rounded-lg p-12 text-center">
          <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground mt-4">Loading observed devices...</p>
        </div>
      ) : devices.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <Eye className="w-16 h-16 text-success mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Devices Under Observation</h3>
          <p className="text-muted-foreground">All devices are either normal or isolated</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {devices.map((device, index) => (
            <motion.div
              key={device.device_id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="glass glass-hover rounded-lg p-6 shadow-glow-yellow"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-3">
                    <Eye className="w-5 h-5 text-warning" />
                    <h3 className="text-lg font-semibold">{device.device_id}</h3>
                    <span className="px-2 py-1 rounded text-xs font-medium bg-warning/20 text-warning">
                      MONITORING
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-4 text-sm mb-4">
                    <div>
                      <span className="text-muted-foreground">Status:</span>
                      <span className="ml-2 font-medium">{device.status}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Risk Score:</span>
                      <span className="ml-2 font-medium">{device.last_risk}/100</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Bandwidth Limit:</span>
                      <span className="ml-2 font-medium">{device.limit_kbps} kbps</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Duration:</span>
                      <span className="ml-2 font-medium flex items-center">
                        <Clock className="w-3 h-3 mr-1" />
                        {Math.floor((Date.now() / 1000 - device.observation_start) / 60)}m
                      </span>
                    </div>
                  </div>

                  <div className="text-sm">
                    <span className="text-muted-foreground">Reason:</span>
                    <p className="mt-1 text-foreground">{device.observation_reason}</p>
                  </div>

                  {device.allowed_outbound && device.allowed_outbound.length > 0 && (
                    <div className="mt-3 text-sm">
                      <span className="text-muted-foreground">Allowed Outbound:</span>
                      <div className="mt-1 flex flex-wrap gap-2">
                        {device.allowed_outbound.map((ip) => (
                          <span key={ip} className="px-2 py-1 bg-card rounded text-xs font-mono">
                            {ip}
                          </span>
                        ))}
                      </div>
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
