"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Activity, FileText, Settings, Target } from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/", icon: Shield },
  { name: "Device Inventory", href: "/devices", icon: Activity },
  { name: "FOX", href: "/threat-intelligence", icon: Target },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
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

      <div className="p-4 border-t border-border text-xs text-muted-foreground">
        Local prototype - no account required. See the collection banner for live status.
      </div>
    </div>
  );
}
