export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "pass" | "fail" | "warn" | "info";

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  evidence: string;
  recommendation: string;
}

export interface CheckResult {
  key: string;
  name: string;
  status: "complete" | "error";
  summary: string;
}

export interface ScanResult {
  scanId: string;
  target: string;
  finalUrl: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  counts: Record<Severity, number>;
  checks: CheckResult[];
  findings: Finding[];
  http: {
    status: number;
    statusText: string;
    responseTimeMs: number;
    contentType: string | null;
    server: string | null;
    redirects: string[];
  };
  tls: {
    https: boolean;
    hsts: boolean;
    certificate: "not-inspected";
  };
  dns: {
    A: string[];
    AAAA: string[];
    MX: string[];
    NS: string[];
    TXT: string[];
    CAA: string[];
  };
  cookies: Array<{
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string | null;
  }>;
  technologies: string[];
  files: {
    robots: { found: boolean; sitemapCount: number; disallowCount: number };
    securityTxt: { found: boolean; contactCount: number; expires: string | null };
  };
}
