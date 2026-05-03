"use client";

import { useState } from "react";
import { Plus, Wifi, WifiOff, Loader2 } from "lucide-react";
import { motion } from "framer-motion";

interface ConnectivityCheck {
  online: boolean;
  ip_address: string | null;
  response_time_ms: number | null;
  message: string;
}

export default function RegisterDevicePage() {
  const [nickname, setNickname] = useState("");
  const [macAddress, setMacAddress] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [deviceType, setDeviceType] = useState("unknown");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [connectivity, setConnectivity] = useState<ConnectivityCheck | null>(null);

  const deviceTypes = [
    { value: "router", label: "Router", icon: "🌐" },
    { value: "phone", label: "Phone", icon: "📱" },
    { value: "laptop", label: "Laptop", icon: "💻" },
    { value: "tablet", label: "Tablet", icon: "📱" },
    { value: "iot", label: "IoT Device", icon: "🔌" },
    { value: "server", label: "Server", icon: "🖥️" },
    { value: "unknown", label: "Unknown", icon: "❓" },
  ];

  const formatMacAddress = (value: string) => {
    // Remove all non-hex characters
    const cleaned = value.replace(/[^0-9A-Fa-f]/g, "");
    
    // Add dashes every 2 characters
    const formatted = cleaned.match(/.{1,2}/g)?.join("-") || cleaned;
    
    return formatted.toUpperCase().slice(0, 17); // Max length: AA-BB-CC-DD-EE-FF
  };

  const handleMacChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const formatted = formatMacAddress(e.target.value);
    setMacAddress(formatted);
  };

  const checkConnectivity = async () => {
    if (!macAddress) {
      setMessage({ type: "error", text: "Please enter MAC address" });
      return;
    }

    setChecking(true);
    setConnectivity(null);
    setMessage(null);

    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      const params = new URLSearchParams({
        mac_address: macAddress,
        ...(ipAddress && { ip_address: ipAddress }),
      });

      const response = await fetch(`${API_URL}/manual-devices/check-connectivity?${params}`, {
        method: "POST",
      });

      if (response.ok) {
        const data = await response.json();
        setConnectivity(data);
        
        if (data.online && data.ip_address && !ipAddress) {
          setIpAddress(data.ip_address);
        }
      } else {
        const error = await response.json();
        setMessage({ type: "error", text: error.detail || "Connectivity check failed" });
      }
    } catch (error) {
      setMessage({ type: "error", text: "Failed to check connectivity" });
    } finally {
      setChecking(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!nickname || !macAddress) {
      setMessage({ type: "error", text: "Please fill in required fields" });
      return;
    }

    setLoading(true);
    setMessage(null);

    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL;
      const response = await fetch(`${API_URL}/manual-devices/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          nickname,
          mac_address: macAddress,
          ip_address: ipAddress || null,
          device_type: deviceType,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        
        // Show verification details
        const verification = data.device?.verification;
        let successMessage = "Device registered successfully!";
        
        if (verification) {
          const details = [];
          if (verification.arp_verified) details.push("✓ ARP verified");
          if (verification.ping_verified) details.push("✓ Ping verified");
          if (verification.response_time_ms) details.push(`${verification.response_time_ms}ms`);
          
          if (details.length > 0) {
            successMessage += ` (${details.join(", ")})`;
          }
        }
        
        setMessage({ type: "success", text: successMessage });
        
        // Reset form
        setTimeout(() => {
          setNickname("");
          setMacAddress("");
          setIpAddress("");
          setDeviceType("unknown");
          setConnectivity(null);
          setMessage(null);
        }, 3000);
      } else {
        const error = await response.json();
        setMessage({ type: "error", text: error.detail || "Registration failed" });
      }
    } catch (error) {
      setMessage({ type: "error", text: "Failed to register device" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-glow flex items-center space-x-3">
          <Plus className="w-8 h-8 text-primary" />
          <span>Manual Device Registration</span>
        </h1>
        <p className="text-muted-foreground mt-2">
          Register devices manually for monitoring and threat detection
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Registration Form */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass rounded-lg p-6"
        >
          <h2 className="text-xl font-semibold mb-4">Device Information</h2>
          
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Device Nickname */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Device Nickname <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={nickname}
                onChange={(e) => setNickname(e.target.value)}
                placeholder="e.g., John's iPhone"
                className="w-full px-4 py-2 bg-background/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                required
              />
            </div>

            {/* MAC Address */}
            <div>
              <label className="block text-sm font-medium mb-2">
                MAC Address <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={macAddress}
                onChange={handleMacChange}
                placeholder="AA-BB-CC-DD-EE-FF"
                className="w-full px-4 py-2 bg-background/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary font-mono"
                required
              />
              <p className="text-xs text-muted-foreground mt-1">
                Format: AA-BB-CC-DD-EE-FF or AA:BB:CC:DD:EE:FF
              </p>
            </div>

            {/* IP Address */}
            <div>
              <label className="block text-sm font-medium mb-2">
                IP Address <span className="text-muted-foreground">(optional)</span>
              </label>
              <input
                type="text"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                placeholder="192.168.0.100"
                className="w-full px-4 py-2 bg-background/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary font-mono"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Leave empty to auto-detect from network
              </p>
            </div>

            {/* Device Type */}
            <div>
              <label className="block text-sm font-medium mb-2">Device Type</label>
              <div className="grid grid-cols-2 gap-2">
                {deviceTypes.map((type) => (
                  <button
                    key={type.value}
                    type="button"
                    onClick={() => setDeviceType(type.value)}
                    className={`px-4 py-2 rounded-lg border transition-colors ${
                      deviceType === type.value
                        ? "bg-primary/20 border-primary text-primary"
                        : "bg-background/50 border-border hover:border-primary/50"
                    }`}
                  >
                    <span className="mr-2">{type.icon}</span>
                    {type.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Connectivity Check Button */}
            <button
              type="button"
              onClick={checkConnectivity}
              disabled={checking || !macAddress}
              className="w-full px-4 py-2 bg-secondary/20 border border-secondary text-secondary rounded-lg hover:bg-secondary/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {checking ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Checking...</span>
                </>
              ) : (
                <>
                  <Wifi className="w-4 h-4" />
                  <span>Verify Connectivity</span>
                </>
              )}
            </button>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading || !nickname || !macAddress}
              className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Registering...</span>
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4" />
                  <span>Register Device</span>
                </>
              )}
            </button>

            {/* Message */}
            {message && (
              <div
                className={`p-4 rounded-lg ${
                  message.type === "success"
                    ? "bg-success/20 text-success border border-success/50"
                    : "bg-destructive/20 text-destructive border border-destructive/50"
                }`}
              >
                {message.text}
              </div>
            )}
          </form>
        </motion.div>

        {/* Info Panel */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="space-y-6"
        >
          {/* Connectivity Status */}
          {connectivity && (
            <div className="glass rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4">Connectivity Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Status:</span>
                  <div className="flex items-center space-x-2">
                    {connectivity.online ? (
                      <>
                        <Wifi className="w-4 h-4 text-success" />
                        <span className="text-success font-medium">Online</span>
                      </>
                    ) : (
                      <>
                        <WifiOff className="w-4 h-4 text-destructive" />
                        <span className="text-destructive font-medium">Offline</span>
                      </>
                    )}
                  </div>
                </div>
                
                {connectivity.ip_address && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">IP Address:</span>
                    <span className="font-mono">{connectivity.ip_address}</span>
                  </div>
                )}
                
                {connectivity.response_time_ms !== null && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Response Time:</span>
                    <span className="font-medium">{connectivity.response_time_ms}ms</span>
                  </div>
                )}
                
                <div className="pt-3 border-t border-border">
                  <p className="text-sm text-muted-foreground">{connectivity.message}</p>
                </div>
              </div>
            </div>
          )}

          {/* Information */}
          <div className="glass rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">What Happens After Registration?</h3>
            <div className="space-y-3 text-sm">
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-primary text-xs font-bold">1</span>
                </div>
                <div>
                  <p className="font-medium">Network Scanning</p>
                  <p className="text-muted-foreground">Nmap scans for open ports and services</p>
                </div>
              </div>
              
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-primary text-xs font-bold">2</span>
                </div>
                <div>
                  <p className="font-medium">Passive Monitoring</p>
                  <p className="text-muted-foreground">Traffic analysis for anomaly detection</p>
                </div>
              </div>
              
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-primary text-xs font-bold">3</span>
                </div>
                <div>
                  <p className="font-medium">Threat Detection</p>
                  <p className="text-muted-foreground">AVIGHNA engine monitors for vulnerabilities</p>
                </div>
              </div>
              
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-primary text-xs font-bold">4</span>
                </div>
                <div>
                  <p className="font-medium">Real-time Alerts</p>
                  <p className="text-muted-foreground">Notifications for suspicious activity</p>
                </div>
              </div>
            </div>
          </div>

          {/* Note */}
          <div className="glass rounded-lg p-6 border-l-4 border-warning">
            <h3 className="text-lg font-semibold mb-2 text-warning">Important Note</h3>
            <p className="text-sm text-muted-foreground">
              Manual registration enables external monitoring only. AVIGHNA performs network-level
              scanning and traffic analysis. Deep internal access requires agent installation on the device.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
