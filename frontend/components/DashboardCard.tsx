"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { ReactNode } from "react";

interface DashboardCardProps {
  title: string;
  count: number;
  icon: ReactNode;
  color: "blue" | "red" | "yellow" | "green" | "orange";
  href: string;
  description: string;
  suffix?: string;
  glow?: "green" | "red" | "yellow" | "orange" | "blue" | "red-pulse";
}

const colorClasses = {
  blue: "border-primary/30",
  red: "border-destructive/30",
  yellow: "border-warning/30",
  green: "border-success/30",
  orange: "border-orange-500/30",
};

const iconColorClasses = {
  blue: "text-primary",
  red: "text-destructive",
  yellow: "text-warning",
  green: "text-success",
  orange: "text-orange-500",
};

const glowStyles = {
  green: { boxShadow: "0 0 15px rgba(34, 197, 94, 0.15)" },
  red: { boxShadow: "0 0 15px rgba(239, 68, 68, 0.15)" },
  yellow: { boxShadow: "0 0 15px rgba(234, 179, 8, 0.15)" },
  orange: { boxShadow: "0 0 15px rgba(249, 115, 22, 0.15)" },
  blue: { boxShadow: "0 0 15px rgba(59, 130, 246, 0.15)" },
  "red-pulse": { 
    boxShadow: "0 0 15px rgba(239, 68, 68, 0.2)",
    animation: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite"
  },
};

export default function DashboardCard({
  title,
  count,
  icon,
  color,
  href,
  description,
  suffix = "",
  glow,
}: DashboardCardProps) {
  return (
    <Link href={href}>
      <motion.div
        whileHover={{ scale: 1.02, y: -4 }}
        whileTap={{ scale: 0.98 }}
        className={`
          glass glass-hover rounded-lg p-6 cursor-pointer relative overflow-hidden
          ${colorClasses[color]}
        `}
        style={glow ? glowStyles[glow] : undefined}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 hover:opacity-100 transition-opacity"></div>
        <div className="relative">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <p className="text-sm text-muted-foreground mb-2">{title}</p>
              <div className="flex items-baseline space-x-2">
                <h2 className="text-4xl font-bold">{count}</h2>
                {suffix && <span className="text-lg text-muted-foreground">{suffix}</span>}
              </div>
              <p className="text-xs text-muted-foreground mt-2">{description}</p>
            </div>
            <div className={`p-3 rounded-lg bg-card ${iconColorClasses[color]}`}>
              {icon}
            </div>
          </div>
        </div>
      </motion.div>
    </Link>
  );
}
