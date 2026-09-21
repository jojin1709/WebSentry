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

export interface DnsResult {
  A: string[];
  AAAA: string[];
  MX: string[];
  NS: string[];
  TXT: string[];
  CAA: string[];
  spf: { found: boolean; policy: string | null };
  dmarc: { found: boolean; policy: string | null; rua: string | null };
}

export interface TlsInfo {
  https: boolean;
  hsts: boolean;
  hstsMaxAge: number | null;
  hstsIncludeSubDomains: boolean;
  hstsPreload: boolean;
  hstsPreloadListed: boolean | null;
  ctLogsFound: boolean;
  certificateIssuer: string | null;
  certificateExpiry: string | null;
}

export interface ExposedPath {
  path: string;
  status: number;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
}

export interface FormInfo {
  action: string;
  method: string;
  hasCsrf: boolean;
  hasAutocompleteOff: boolean;
  inputTypes: string[];
}

export interface SeoResult {
  title: string | null;
  description: string | null;
  canonical: string | null;
  ogTitle: string | null;
  ogDescription: string | null;
  ogImage: string | null;
  robots: string | null;
  viewport: string | null;
  lang: string | null;
  headings: Record<string, number>;
}

export interface CorsDetail {
  allowOrigin: string | null;
  allowMethods: string | null;
  allowHeaders: string | null;
  allowCredentials: string | null;
  maxAge: string | null;
  exposeHeaders: string | null;
  preflightRequired: boolean;
}

export interface SriResult {
  totalScripts: number;
  externalScripts: number;
  scriptsWithIntegrity: number;
  totalLinks: number;
  externalLinks: number;
  linksWithIntegrity: number;
}

export interface PerformanceResult {
  responseTimeMs: number;
  pageSizeBytes: number;
  pageSizeFormatted: string;
  resourceCount: { scripts: number; stylesheets: number; images: number; iframes: number; fonts: number; other: number };
  renderBlockingScripts: number;
  renderBlockingStyles: number;
  totalScriptSize: string;
  totalStyleSize: string;
}

export interface A11yResult {
  imagesTotal: number;
  imagesWithAlt: number;
  imagesWithEmptyAlt: number;
  formsTotal: number;
  formsWithLabels: number;
  inputsTotal: number;
  inputsWithLabels: number;
  headingStructure: Record<string, number>;
  hasH1: boolean;
  h1Count: number;
  hasLang: boolean;
  hasSkipLink: boolean;
  hasAriaLandmarks: boolean;
  hasRoleAttributes: number;
}

export interface InfraResult {
  http2: boolean | null;
  http3: boolean | null;
  ipv6: boolean;
  dnssec: boolean | null;
  serverTiming: string | null;
  altSvc: string | null;
}

export interface JwtInfo {
  found: boolean;
  locations: string[];
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
  tls: TlsInfo;
  dns: DnsResult;
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
  exposedPaths: ExposedPath[];
  forms: FormInfo[];
  seo: SeoResult;
  corsDetail: CorsDetail;
  sri: SriResult;
  performance: PerformanceResult;
  accessibility: A11yResult;
  infrastructure: InfraResult;
  jwt: JwtInfo;
}
