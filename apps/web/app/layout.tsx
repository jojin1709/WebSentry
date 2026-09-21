import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WebSentry — Website Security Monitor",
  description: "Privacy-first, ephemeral website security analysis. No account and no scan history.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
