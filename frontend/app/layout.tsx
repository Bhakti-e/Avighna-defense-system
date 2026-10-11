import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import ClientLayout from "@/components/ClientLayout";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AVIGHNA Defense v1.0",
  description: "Network Defense & Threat Detection Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <ClientLayout>
          <div role="status" className="border-b border-amber-500/40 bg-amber-950 px-4 py-2 text-center text-sm text-amber-100">
            Offline preview — collection and actions are disabled. Existing intelligence widgets may show demo data.
          </div>
          {children}
        </ClientLayout>
      </body>
    </html>
  );
}
