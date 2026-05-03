"use client";

import { useEffect, useState } from "react";
import { Shield, ExternalLink, AlertTriangle, Info, TrendingUp } from "lucide-react";

interface ThreatFeed {
  title: string;
  source: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  timestamp: string;
  summary: string;
  link: string;
}

export default function ThreatIntelligencePage() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Placeholder - real threat intelligence feeds integration pending
    setLoading(false);
    
    // Example structure (not real data)
    setFeeds([]);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-500 bg-red-500/20 border-red-500/50";
      case "high":
        return "text-orange-500 bg-orange-500/20 border-orange-500/50";
      case "medium":
        return "text-yellow-500 bg-yellow-500/20 border-yellow-500/50";
      case "low":
        return "text-blue-500 bg-blue-500/20 border-blue-500/50";
      default:
        return "text-gray-500 bg-gray-500/20 border-gray-500/50";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
      case "high":
        return <AlertTriangle className="w-4 h-4" />;
      case "medium":
        return <TrendingUp className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold flex items-center space-x-3">
          <Shield className="w-8 h-8 text-primary" />
          <span>FOX Threat Intelligence Center</span>
        </h1>
        <p className="text-muted-foreground mt-2">
          Real-time cybersecurity intelligence and threat feeds
        </p>
      </div>

      {/* Integration Status */}
      <div className="glass rounded-lg p-6 border-l-4 border-warning">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-warning mt-0.5" />
          <div>
            <h3 className="font-semibold text-warning">External Feed Integration Pending</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Threat intelligence feeds from CISA, MITRE, NVD, KrebsOnSecurity, Cisco Talos, 
              The Hacker News, MalwareBazaar, and AlienVault OTX are currently being integrated.
            </p>
            <p className="text-sm text-muted-foreground mt-2">
              This module will display:
            </p>
            <ul className="text-sm text-muted-foreground mt-2 space-y-1 ml-4">
              <li>• Recent CVEs and vulnerability disclosures</li>
              <li>• Threat actor activity and campaigns</li>
              <li>• Malware analysis and indicators</li>
              <li>• Security advisories and breach reports</li>
              <li>• Real-time threat intelligence updates</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Planned Sources */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[
          { name: "CISA", desc: "Cybersecurity & Infrastructure Security Agency", status: "pending" },
          { name: "MITRE ATT&CK", desc: "Adversarial tactics and techniques", status: "pending" },
          { name: "NVD", desc: "National Vulnerability Database", status: "pending" },
          { name: "KrebsOnSecurity", desc: "In-depth security news", status: "pending" },
          { name: "Cisco Talos", desc: "Threat intelligence and research", status: "pending" },
          { name: "The Hacker News", desc: "Cybersecurity news platform", status: "pending" },
          { name: "MalwareBazaar", desc: "Malware sample database", status: "pending" },
          { name: "AlienVault OTX", desc: "Open Threat Exchange", status: "pending" },
        ].map((source) => (
          <div key={source.name} className="glass rounded-lg p-4">
            <div className="flex items-start justify-between mb-2">
              <h3 className="font-semibold">{source.name}</h3>
              <span className="text-xs px-2 py-1 rounded bg-warning/20 text-warning border border-warning/50">
                Pending
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{source.desc}</p>
          </div>
        ))}
      </div>

      {/* Current CTI Data (from backend) */}
      <div className="glass rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">Current Threat Data</h2>
        <p className="text-sm text-muted-foreground mb-4">
          AVIGHNA currently monitors threat feeds from abuse.ch (URLhaus, ThreatFox, Feodo Tracker).
          This data is used internally for threat correlation.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-background/50 rounded-lg border border-border">
            <div className="text-2xl font-bold text-primary">Active</div>
            <div className="text-sm text-muted-foreground mt-1">URLhaus Feed</div>
          </div>
          <div className="p-4 bg-background/50 rounded-lg border border-border">
            <div className="text-2xl font-bold text-primary">Active</div>
            <div className="text-sm text-muted-foreground mt-1">ThreatFox Feed</div>
          </div>
          <div className="p-4 bg-background/50 rounded-lg border border-border">
            <div className="text-2xl font-bold text-primary">Active</div>
            <div className="text-sm text-muted-foreground mt-1">Feodo Tracker</div>
          </div>
        </div>
      </div>

      {/* Coming Soon */}
      <div className="glass rounded-lg p-6 text-center">
        <Shield className="w-12 h-12 text-primary mx-auto mb-4" />
        <h3 className="text-lg font-semibold mb-2">Enhanced Threat Intelligence Coming Soon</h3>
        <p className="text-sm text-muted-foreground max-w-2xl mx-auto">
          We're working on integrating comprehensive threat intelligence feeds to provide you with 
          real-time security insights, vulnerability alerts, and threat actor tracking.
        </p>
      </div>
    </div>
  );
}
