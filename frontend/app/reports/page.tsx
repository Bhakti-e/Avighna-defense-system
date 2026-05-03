"use client";

import { useState, useEffect } from "react";
import { FileText, Download, Calendar, AlertTriangle } from "lucide-react";

interface Report {
  id: number;
  device_mac: string;
  device_ip: string;
  risk_score: number;
  threat_type: string;
  generated_at: string;
  filename: string;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch("http://localhost:8000/reports/list");
      if (response.ok) {
        const data = await response.json();
        setReports(data.reports || []);
      }
    } catch (error) {
      console.error("Failed to fetch reports:", error);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (reportId: number, filename: string) => {
    try {
      const response = await fetch(`http://localhost:8000/reports/download/${reportId}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert("Failed to download report");
      }
    } catch (error) {
      console.error("Download error:", error);
      alert("Failed to download report");
    }
  };

  const generateReport = async () => {
    const mac = prompt("Enter device MAC address:");
    if (!mac) return;

    try {
      const response = await fetch("http://localhost:8000/reports/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_mac: mac }),
      });

      if (response.ok) {
        alert("Report generated successfully");
        fetchReports();
      } else {
        const error = await response.json();
        alert(`Failed to generate report: ${error.detail}`);
      }
    } catch (error) {
      console.error("Generate error:", error);
      alert("Failed to generate report");
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return "text-red-500";
    if (score >= 50) return "text-yellow-500";
    return "text-green-500";
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading reports...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <FileText className="w-8 h-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold">Forensic Reports</h1>
            <p className="text-muted-foreground">Generated threat analysis reports</p>
          </div>
        </div>
        
        <button
          onClick={generateReport}
          className="px-6 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
        >
          Generate Report
        </button>
      </div>

      {reports.length === 0 ? (
        <div className="glass p-12 rounded-lg text-center">
          <FileText className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Reports Generated</h3>
          <p className="text-muted-foreground">
            Generate forensic reports for devices with detected threats
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {reports.map((report) => (
            <div key={report.id} className="glass p-6 rounded-lg hover:border-primary/50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <AlertTriangle className={`w-5 h-5 ${getRiskColor(report.risk_score)}`} />
                    <h3 className="text-lg font-semibold">{report.threat_type}</h3>
                    <span className={`text-sm font-bold ${getRiskColor(report.risk_score)}`}>
                      Risk: {report.risk_score}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Device MAC:</span>
                      <span className="ml-2 font-mono">{report.device_mac}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Device IP:</span>
                      <span className="ml-2 font-mono">{report.device_ip}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Calendar className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">
                        {new Date(report.generated_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
                
                <button
                  onClick={() => downloadReport(report.id, report.filename)}
                  className="ml-6 px-4 py-2 bg-primary/20 text-primary rounded-lg hover:bg-primary/30 transition-colors flex items-center space-x-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Download PDF</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
