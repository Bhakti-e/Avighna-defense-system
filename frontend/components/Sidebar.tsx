"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { 
  Shield, 
  Activity, 
  Eye, 
  AlertTriangle, 
  FileText, 
  Settings, 
  Plus,
  Target,
  LogOut,
  User
} from "lucide-react";
import { useState, useEffect } from "react";

const navigation = [
  { name: "Dashboard", href: "/", icon: Shield },
  { name: "Register Device", href: "/register", icon: Plus },
  { name: "FOX", href: "/threat-intelligence", icon: Target },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [username, setUsername] = useState<string | null>(null);

  useEffect(() => {
    // Get username from localStorage
    const user = localStorage.getItem("avighna_user");
    setUsername(user);
  }, []);

  const handleLogout = () => {
    // Clear auth data
    localStorage.removeItem("avighna_token");
    localStorage.removeItem("avighna_user");
    
    // Redirect to login
    router.push("/login");
  };

  return (
    <div className="w-64 glass border-r border-border flex flex-col">
      <div className="p-6 border-b border-border">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-primary" />
          <div>
            <h1 className="text-xl font-bold">AVIGHNA</h1>
            <p className="text-xs text-muted-foreground">Defense v1.0</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`
                flex items-center space-x-3 px-4 py-3 rounded-lg
                transition-all duration-200
                ${isActive 
                  ? "bg-primary text-white" 
                  : "text-muted-foreground hover:bg-card hover:text-foreground"
                }
              `}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* System Status & Logout */}
      <div className="p-4 border-t border-border space-y-3">
        {/* System Status */}
        <div className="glass p-3 rounded-lg">
          <div className="text-xs space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Monitoring</span>
              <span className="flex items-center text-success text-xs">
                <span className="w-1.5 h-1.5 bg-success rounded-full mr-1.5"></span>
                Active
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Backend</span>
              <span className="flex items-center text-success text-xs">
                <span className="w-1.5 h-1.5 bg-success rounded-full mr-1.5"></span>
                Connected
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Last Scan</span>
              <span className="text-xs">2m ago</span>
            </div>
          </div>
        </div>

        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg bg-card hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors text-sm"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
}
