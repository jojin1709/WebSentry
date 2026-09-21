import type { Finding, TlsInfo } from "../types";

interface CtEntry {
  issuer_name?: string;
  not_before?: string;
  not_after?: string;
  common_name?: string;
  name_value?: string;
}

export async function scanTls(
  hostname: string,
  finalUrl: URL,
  hstsHeader: string | null,
  timeoutMs: number,
): Promise<{ findings: Finding[]; tls: TlsInfo }> {
  const findings: Finding[] = [];
  const tls: TlsInfo = {
    https: finalUrl.protocol === "https:",
    hsts: Boolean(hstsHeader),
    hstsMaxAge: null,
    hstsIncludeSubDomains: false,
    hstsPreload: false,
    hstsPreloadListed: null,
    ctLogsFound: false,
    certificateIssuer: null,
    certificateExpiry: null,
  };

  if (!tls.https) {
    findings.push({
      id: "tls-not-https",
      category: "TLS",
      severity: "high",
      status: "fail",
      title: "Site is not served over HTTPS",
      evidence: `The final URL uses ${finalUrl.protocol}//${finalUrl.host}.`,
      recommendation: "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
    });
    return { findings, tls };
  }

  if (hstsHeader) {
    const lower = hstsHeader.toLowerCase();
    const maxAgeMatch = lower.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      tls.hstsMaxAge = parseInt(maxAgeMatch[1], 10);
      if (tls.hstsMaxAge < 15552000) {
        findings.push({
          id: "tls-hsts-low-max-age",
          category: "TLS",
          severity: "medium",
          status: "fail",
          title: "HSTS max-age is too short",
          evidence: `max-age=${tls.hstsMaxAge} (${Math.round(tls.hstsMaxAge / 86400)} days). Recommended minimum is 6 months (15552000 seconds).`,
          recommendation: "Set max-age to at least 15552000 (6 months). Consider 31536000 (1 year) for production sites.",
        });
      } else {
        findings.push({
          id: "tls-hsts-max-age",
          category: "TLS",
          severity: "info",
          status: "pass",
          title: "HSTS max-age is adequate",
          evidence: `max-age=${tls.hstsMaxAge} (${Math.round(tls.hstsMaxAge / 86400)} days).`,
          recommendation: "Keep the HSTS policy under review.",
        });
      }
    } else {
      findings.push({
        id: "tls-hsts-no-max-age",
        category: "TLS",
        severity: "medium",
        status: "fail",
        title: "HSTS header is missing max-age directive",
        evidence: `Strict-Transport-Security: ${hstsHeader}`,
        recommendation: "Include a max-age directive with a value of at least 15552000.",
      });
    }

    tls.hstsIncludeSubDomains = lower.includes("includesubdomains");
    if (!tls.hstsIncludeSubDomains) {
      findings.push({
        id: "tls-hsts-no-subdomains",
        category: "TLS",
        severity: "low",
        status: "warn",
        title: "HSTS includeSubDomains is not set",
        evidence: "The HSTS header does not include the includeSubDomains directive.",
        recommendation: "Add includeSubDomains to protect all subdomains from protocol downgrade attacks.",
      });
    }

    tls.hstsPreload = lower.includes("preload");
    if (!tls.hstsPreload) {
      findings.push({
        id: "tls-hsts-no-preload",
        category: "TLS",
        severity: "info",
        status: "info",
        title: "HSTS preload directive is not set",
        evidence: "The HSTS header does not include the preload directive.",
        recommendation: "Add preload and submit to hstspreload.org for browser preloading if appropriate.",
      });
    }
  } else {
    findings.push({
      id: "tls-no-hsts",
      category: "TLS",
      severity: "medium",
      status: "fail",
      title: "Strict-Transport-Security header is missing",
      evidence: "No HSTS header was observed on the HTTPS response.",
      recommendation: "Add a Strict-Transport-Security header with max-age=15552000; includeSubDomains; preload.",
    });
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {
      signal: controller.signal,
      cf: { cacheTtl: 3600 },
    });
    clearTimeout(timer);
    if (res.ok) {
      const entries: CtEntry[] = await res.json();
      if (entries.length > 0) {
        tls.ctLogsFound = true;
        const latest = entries[0];
        if (latest.issuer_name) tls.certificateIssuer = latest.issuer_name;
        if (latest.not_after) tls.certificateExpiry = latest.not_after;

        const now = Date.now();
        const expiry = latest.not_after ? new Date(latest.not_after).getTime() : 0;
        if (expiry && expiry < now) {
          findings.push({
            id: "tls-cert-expired",
            category: "TLS",
            severity: "critical",
            status: "fail",
            title: "Certificate has expired",
            evidence: `Certificate expired on ${latest.not_after}. Issuer: ${latest.issuer_name}.`,
            recommendation: "Renew the certificate immediately. Consider automating certificate renewal.",
          });
        } else if (expiry && expiry - now < 30 * 86400000) {
          findings.push({
            id: "tls-cert-expiring-soon",
            category: "TLS",
            severity: "medium",
            status: "warn",
            title: "Certificate is expiring soon",
            evidence: `Certificate expires on ${latest.not_after} (${Math.round((expiry - now) / 86400000)} days).`,
            recommendation: "Renew the certificate and set up automated renewal.",
          });
        } else if (expiry) {
          findings.push({
            id: "tls-cert-valid",
            category: "TLS",
            severity: "info",
            status: "pass",
            title: "Certificate is valid",
            evidence: `Expires: ${latest.not_after}. Issuer: ${latest.issuer_name}.`,
            recommendation: "Keep certificate renewal automated.",
          });
        }

        findings.push({
          id: "tls-ct-logs",
          category: "TLS",
          severity: "info",
          status: "pass",
          title: "Certificate Transparency logs found",
          evidence: `${entries.length} CT log entries found for ${hostname}.`,
          recommendation: "CT logging is working as expected.",
        });
      }
    }
  } catch {}

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch("https://hstspreload.org/api/v2/status?domain=" + encodeURIComponent(hostname), {
      signal: controller.signal,
      cf: { cacheTtl: 3600 },
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as { status?: string };
      tls.hstsPreloadListed = data.status === "present";
      if (data.status === "present") {
        findings.push({
          id: "tls-hsts-preloaded",
          category: "TLS",
          severity: "info",
          status: "pass",
          title: "Domain is on the HSTS preload list",
          evidence: `${hostname} is included in the HSTS preload list.`,
          recommendation: "Maintain HSTS with max-age >= 31536000 and includeSubDomains to stay on the preload list.",
        });
      }
    }
  } catch {}

  return { findings, tls };
}
