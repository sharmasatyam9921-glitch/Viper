import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { QueryProvider } from "@/providers/QueryProvider";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";
import { ThemeScript } from "@/components/ThemeScript";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "VIPER · Dashboard",
  description: "Autonomous bug-bounty + agentic-AI red-team hunting engine",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      style={{ fontFamily: "var(--font-geist-sans)" }}
      suppressHydrationWarning
    >
      <body
        className="min-h-full"
        style={{ background: "var(--surface-0)", color: "var(--ink-1)" }}
        suppressHydrationWarning
      >
        <ThemeScript />
        <QueryProvider>
          <Sidebar />
          <TopBar />
          <main className="ml-60 mt-14 px-8 py-8 max-w-[1480px]">{children}</main>
        </QueryProvider>
      </body>
    </html>
  );
}
