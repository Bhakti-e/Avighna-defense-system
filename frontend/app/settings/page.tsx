"use client";

import { useState } from "react";
import { Settings, Bell, Activity, Wifi, Key } from "lucide-react";

export default function SettingsPage() {
  const [scanFrequency, setScanFrequency] = useState("300");
  const [notifications, setNotifications] = useState({
    highRisk: true,
    mediumRisk: true,
    lowRisk: false,
    newDevice: true,
    portScan: true,
  });

  const handleSave = () => {
    alert("System settings saved successfully");
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center space-x-3">
        <Settings className="w-8 h-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">System Settings</h1>
          <p className="text-muted-foreground">Configure AVIGHNA system preferences</p>
        </div>
      </div>

      <div className="grid gap-6 max-w-2xl">
        {/* Notification Preferences */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <Bell className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Notification Preferences</h2>
          </div>
          
          <div className="space-y-3">
            {Object.entries(notifications).map(([key, value]) => (
              <label key={key} className="flex items-center justify-between cursor-pointer">
                <span className="text-sm capitalize">
                  {key.replace(/([A-Z])/g, " $1").trim()}
                </span>
                <input
                  type="checkbox"
                  checked={value}
                  onChange={(e) =>
                    setNotifications({ ...notifications, [key]: e.target.checked })
                  }
                  className="w-5 h-5 text-primary rounded focus:ring-2 focus:ring-primary"
                />
              </label>
            ))}
          </div>
        </div>

        {/* Scan Settings */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <Activity className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Scan Settings</h2>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">
              Network Scan Frequency (seconds)
            </label>
            <input
              type="number"
              value={scanFrequency}
              onChange={(e) => setScanFrequency(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              min="60"
              max="3600"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Current: {scanFrequency}s (recommended: 300s)
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">
              Threat Detection Threshold
            </label>
            <select className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary">
              <option value="low">Low - Detect all suspicious activity</option>
              <option value="medium" selected>Medium - Balanced detection</option>
              <option value="high">High - Only critical threats</option>
            </select>
          </div>
        </div>

        {/* Router Integration (Placeholder) */}
        <div className="glass p-6 rounded-lg space-y-4 opacity-60">
          <div className="flex items-center space-x-2 mb-4">
            <Wifi className="w-5 h-5 text-muted-foreground" />
            <h2 className="text-xl font-semibold">Router Integration</h2>
            <span className="text-xs bg-muted px-2 py-1 rounded">Coming Soon</span>
          </div>
          
          <p className="text-sm text-muted-foreground">
            Router-level enforcement and traffic control will be available in future updates.
          </p>
        </div>

        {/* API Configuration (Placeholder) */}
        <div className="glass p-6 rounded-lg space-y-4 opacity-60">
          <div className="flex items-center space-x-2 mb-4">
            <Key className="w-5 h-5 text-muted-foreground" />
            <h2 className="text-xl font-semibold">API Configuration</h2>
            <span className="text-xs bg-muted px-2 py-1 rounded">Coming Soon</span>
          </div>
          
          <p className="text-sm text-muted-foreground">
            External threat intelligence API integration will be available in future updates.
          </p>
        </div>

        {/* Report Settings */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <Activity className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Report Settings</h2>
          </div>
          
          <div className="space-y-3">
            <label className="flex items-center justify-between cursor-pointer">
              <span className="text-sm">Auto-generate reports for isolated devices</span>
              <input
                type="checkbox"
                defaultChecked
                className="w-5 h-5 text-primary rounded focus:ring-2 focus:ring-primary"
              />
            </label>
            <label className="flex items-center justify-between cursor-pointer">
              <span className="text-sm">Include forensic data in reports</span>
              <input
                type="checkbox"
                defaultChecked
                className="w-5 h-5 text-primary rounded focus:ring-2 focus:ring-primary"
              />
            </label>
          </div>
        </div>

        {/* Save Button */}
        <button
          onClick={handleSave}
          className="w-full py-3 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors font-medium"
        >
          Save System Settings
        </button>
      </div>
    </div>
  );
}
