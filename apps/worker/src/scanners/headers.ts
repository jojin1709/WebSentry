import type { Finding } from "../types";

const headers = [
  ["content-security-policy", "Content-Security-Policy", "medium"],
  ["strict-transport-security", "Strict-Transport-Security", "medium"],
  ["x-content-type-options", "X-Content-Type-Options", "low"],
  ["x-frame-options", "X-Frame-Options", "low"],
  ["referrer-policy", "Referrer-Policy", "low"],
  ["permissions-policy", "Permissions-Policy", "info"],
  ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "info"],
  ["cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "info"],
] as const;

export function scanHeaders(response: Response): Finding[] {
  const findings: Finding[] = [];
  for (const [key, name, severity] of headers) {
    const value = response.headers.get(key);
    if (!value) {
      const actualSeverity = key === "strict-transport-security" && new URL(response.url).protocol === "https:" ? "medium" : severity;
      findings.push({
        id: `header-${key}`,
        category: "Security Headers",
        severity: actualSeverity,
        status: actualSeverity === "info" ? "info" : "fail",
        title: `${name} is missing`,
        evidence: `No ${name} response header was observed.`,
        recommendation: `Review whether ${name} is appropriate for the application and configure it deliberately.`,
      });
      continue;
    }
    findings.push({
      id: `header-${key}`,
      category: "Security Headers",
      severity: "info",
      status: "pass",
      title: `${name} is present`,
      evidence: value.slice(0, 500),
      recommendation: "Keep the policy reviewed and aligned with the application.",
    });
  }
  return findings;
}
