"use client";

import { useEffect, useState } from "react";
import { Bell, Shield, AlertTriangle, ChevronDown, User, Settings, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";

export default function Topbar() {
  const router = useRouter();
  const [stats, setStats] = useState({ devices: 0, alerts: 0 });
  const [username, setUsername] = useState("User");
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);

  useEffect(() => {
    // Get username
    const user = localStorage.getItem("avighna_user");
    if (user) setUsername(user);

    fetchStats();
    fetchNotifications();
    const interval = setInterval(() => {
      fetchStats();
      fetchNotifications();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const [devicesRes, alertsRes] = await Promise.all([
        fetch(`${API_URL}/devices/`),
        fetch(`${API_URL}/alerts/`),
      ]);
      
      if (!devicesRes.ok || !alertsRes.ok) {
        console.error("API request failed:", devicesRes.status, alertsRes.status);
        return;
      }
      
      const devices = await devicesRes.json();
      const alertsData = await alertsRes.json();
      
      setStats({
        devices: Array.isArray(devices) ? devices.length : 0,
        alerts: alertsData.count || alertsData.alerts?.length || 0,
      });
    } catch (error) {
      console.error("Failed to fetch topbar stats:", error);
    }
  };

  const fetchNotifications = async () => {
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const [alertsRes, reconRes] = await Promise.all([
        fetch(`${API_URL}/alerts/`),
        fetch(`${API_URL}/reconnaissance/findings`),
      ]);
      
      const alerts = await alertsRes.json();
      const recon = await reconRes.json();
      
      const notifs: any[] = [];
      
      // Add alerts
      if (Array.isArray(alerts)) {
        alerts.slice(0, 5).forEach((alert: any) => {
          notifs.push({
            type: "alert",
            title: alert.reason || "Security Alert",
            time: new Date(alert.timestamp).toLocaleTimeString(),
            severity: alert.severity
          });
        });
      }
      
      // Add recon events
      if (Array.isArray(recon)) {
        recon.slice(0, 3).forEach((event: any) => {
          notifs.push({
            type: "recon",
            title: `Port scan detected: ${event.source_ip}`,
            time: new Date(event.timestamp).toLocaleTimeString(),
            severity: 3
          });
        });
      }
      
      setNotifications(notifs);
    } catch (error) {
      console.error("Failed to fetch notifications:", error);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("avighna_token");
    localStorage.removeItem("avighna_user");
    router.push("/login");
  };

  return (
    <div className="glass border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-success" />
            <span className="text-sm font-medium">{stats.devices} Devices</span>
          </div>
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-destructive" />
            <span className="text-sm font-medium">{stats.alerts} Alerts</span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          {/* Notification Bell */}
          <div className="relative">
            <button 
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-lg hover:bg-card transition-colors"
            >
              <Bell className="w-5 h-5" />
              {notifications.length > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-destructive rounded-full animate-pulse"></span>
              )}
            </button>

            {/* Notifications Dropdown */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 glass rounded-lg shadow-lg border border-border z-[9999]">
                <div className="p-4 border-b border-border">
                  <h3 className="font-semibold">Notifications</h3>
                </div>
                <div className="max-h-96 overflow-y-auto">
                  {notifications.length === 0 ? (
                    <div className="p-4 text-center text-muted-foreground">
                      No new notifications
                    </div>
                  ) : (
                    notifications.map((notif, idx) => (
                      <div key={idx} className="p-3 border-b border-border hover:bg-card/50 cursor-pointer">
                        <div className="flex items-start space-x-2">
                          <AlertTriangle className={`w-4 h-4 mt-1 ${
                            notif.severity >= 4 ? "text-destructive" : "text-warning"
                          }`} />
                          <div className="flex-1">
                            <p className="text-sm font-medium">{notif.title}</p>
                            <p className="text-xs text-muted-foreground">{notif.time}</p>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
          
          {/* Profile Dropdown */}
          <div className="relative">
            <button 
              onClick={() => setShowProfileMenu(!showProfileMenu)}
              className="flex items-center space-x-2 px-3 py-2 rounded-lg hover:bg-card transition-colors"
            >
              <span className="w-2 h-2 bg-success rounded-full"></span>
              <span className="text-sm font-medium">{username}</span>
              <ChevronDown className="w-4 h-4" />
            </button>

            {/* Profile Menu Dropdown */}
            {showProfileMenu && (
              <div className="absolute right-0 mt-2 w-48 glass rounded-lg shadow-lg border border-border z-[9999]">
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    router.push("/profile");
                  }}
                  className="w-full flex items-center space-x-2 px-4 py-3 hover:bg-card transition-colors text-left rounded-t-lg"
                >
                  <User className="w-4 h-4" />
                  <span>Profile</span>
                </button>
                <div className="border-t border-border"></div>
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center space-x-2 px-4 py-3 hover:bg-destructive/20 text-destructive transition-colors text-left rounded-b-lg"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Logout</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
