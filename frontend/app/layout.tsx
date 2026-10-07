import type { Metadata } from "next";
import "./globals.css";
import ShellLayout from "@/components/layout/ShellLayout";

export const metadata: Metadata = {
  title: "CYBERGUARD — Enterprise Cyber Threat, Phishing & Impersonation Defense",
  description: "AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        <ShellLayout>{children}</ShellLayout>
      </body>
    </html>
  );
}
