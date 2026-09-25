import type { Metadata } from "next";

import { Providers } from "@/components/providers";

import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis AI Security",
  description:
    "Authorized security assessment platform for Generative AI applications, agents, and their supporting APIs.",
  // No icon file is served, and none should be fetched from anywhere else.
  // Without this, every browser issues its own GET /favicon.ico, which
  // 404s and surfaces as a console error on first load.
  icons: { icon: "data:," },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
