import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import ClientLayout from "@/components/ClientLayout";
import CollectionStatus from "@/components/CollectionStatus";

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
          <CollectionStatus />
          {children}
        </ClientLayout>
      </body>
    </html>
  );
}
