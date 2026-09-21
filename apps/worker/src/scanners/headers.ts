import type { Finding } from "../types";

export function scanHeaders(response: Response): Finding[] {
  const findings: Finding[] = [];
  const url = new URL(response.url);

  const headerChecks: Array<{
    key: string;
    name: string;
    missingSeverity: "medium" | "low" | "info";
    analyze?: (value: string) => Finding[];
  }> = [
    {
      key: "content-security-policy",
      name: "Content-Security-Policy",
      missingSeverity: "medium",
      analyze(value) {
        const f: Finding[] = [];
        const lower = value.toLowerCase();
        if (lower.includes("'unsafe-inline'")) {
          f.push({ id: "csp-unsafe-inline", category: "Security Headers", severity: "medium", status: "fail", title: "CSP allows unsafe-inline", evidence: `CSP contains 'unsafe-inline': ${value.slice(0, 300)}`, recommendation: "Remove 'unsafe-inline' and use nonces or hashes for inline scripts and styles." });
        }
        if (lower.includes("'unsafe-eval'")) {
          f.push({ id: "csp-unsafe-eval", category: "Security Headers", severity: "high", status: "fail", title: "CSP allows unsafe-eval", evidence: `CSP contains 'unsafe-eval': ${value.slice(0, 300)}`, recommendation: "Remove 'unsafe-eval' to prevent code injection via eval(). If needed, use 'wasm-unsafe-eval' instead." });
        }
        if (lower.includes("script-src") && !lower.includes("'strict-dynamic'") && !lower.includes("'nonce-") && !lower.includes("'sha")) {
          if (lower.includes("'unsafe-inline'") || (!lower.includes("'nonce-") && !lower.includes("'sha"))) {
            f.push({ id: "csp-weak-script-src", category: "Security Headers", severity: "medium", status: "warn", title: "CSP script-src may be too permissive", evidence: `script-src policy: ${value.slice(0, 300)}`, recommendation: "Use nonce-based or hash-based script-src for stronger XSS protection." });
          }
        }
        if (!lower.includes("default-src") && !lower.includes("script-src")) {
          f.push({ id: "csp-no-default-src", category: "Security Headers", severity: "low", status: "warn", title: "CSP has no default-src directive", evidence: `CSP: ${value.slice(0, 300)}`, recommendation: "Add default-src as a fallback for directives that are not explicitly set." });
        }
        if (lower.includes("frame-ancestors '*'")) {
          f.push({ id: "csp-frame-ancestors-wildcard", category: "Security Headers", severity: "medium", status: "fail", title: "CSP frame-ancestors uses wildcard", evidence: `frame-ancestors is '*', allowing any origin to embed this page.`, recommendation: "Restrict frame-ancestors to specific trusted origins." });
        }
        return f;
      },
    },
    {
      key: "strict-transport-security",
      name: "Strict-Transport-Security",
      missingSeverity: "medium",
      analyze(value) {
        const lower = value.toLowerCase();
        const f: Finding[] = [];
        const maxAgeMatch = lower.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1], 10);
          if (maxAge < 15552000) {
            f.push({ id: "hsts-low-max-age", category: "Security Headers", severity: "medium", status: "fail", title: "HSTS max-age is too short", evidence: `max-age=${maxAge} (${Math.round(maxAge / 86400)} days). Recommended: 15552000+ (6 months).`, recommendation: "Increase max-age to at least 15552000 (6 months) for production sites." });
          }
        }
        if (!lower.includes("includesubdomains")) {
          f.push({ id: "hsts-no-include-subdomains", category: "Security Headers", severity: "low", status: "warn", title: "HSTS missing includeSubDomains", evidence: "The HSTS header does not include includeSubDomains.", recommendation: "Add includeSubDomains to protect all subdomains." });
        }
        if (!lower.includes("preload")) {
          f.push({ id: "hsts-no-preload", category: "Security Headers", severity: "info", status: "info", title: "HSTS preload not set", evidence: "The HSTS header does not include preload.", recommendation: "Add preload and submit to hstspreload.org." });
        }
        return f;
      },
    },
    {
      key: "x-content-type-options",
      name: "X-Content-Type-Options",
      missingSeverity: "low",
      analyze(value) {
        if (value.toLowerCase() !== "nosniff") {
          return [{ id: "xcto-wrong-value", category: "Security Headers", severity: "low", status: "warn", title: "X-Content-Type-Options has unexpected value", evidence: `Value: ${value}. Expected: nosniff.`, recommendation: "Set X-Content-Type-Options to nosniff." }];
        }
        return [];
      },
    },
    {
      key: "x-frame-options",
      name: "X-Frame-Options",
      missingSeverity: "low",
      analyze(value) {
        const v = value.toUpperCase().trim();
        if (v !== "DENY" && v !== "SAMEORIGIN") {
          return [{ id: "xfo-unexpected-value", category: "Security Headers", severity: "low", status: "warn", title: "X-Frame-Options has unexpected value", evidence: `Value: ${value}. Expected DENY or SAMEORIGIN.`, recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN." }];
        }
        return [];
      },
    },
    {
      key: "referrer-policy",
      name: "Referrer-Policy",
      missingSeverity: "low",
      analyze(value) {
        const lower = value.toLowerCase().trim();
        const safe = ["no-referrer", "no-referrer-when-downgrade", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"];
        if (lower === "unsafe-url" || lower === "unsafe-no-referrer") {
          return [{ id: "rp-unsafe", category: "Security Headers", severity: "medium", status: "fail", title: "Referrer-Policy is unsafe", evidence: `Value: ${value}. This may leak sensitive URL information.`, recommendation: "Use strict-origin-when-cross-origin or no-referrer." }];
        }
        if (!safe.some((s) => lower.includes(s))) {
          return [{ id: "rp-unusual", category: "Security Headers", severity: "info", status: "warn", title: "Referrer-Policy has an unusual value", evidence: `Value: ${value}`, recommendation: "Consider using strict-origin-when-cross-origin for balanced referrer control." }];
        }
        return [];
      },
    },
    {
      key: "permissions-policy",
      name: "Permissions-Policy",
      missingSeverity: "info",
      analyze(value) {
        const f: Finding[] = [];
        const lower = value.toLowerCase();
        const dangerous = ["camera", "microphone", "geolocation", "payment", "usb", "magnetometer", "gyroscope", "accelerometer"];
        for (const feature of dangerous) {
          if (lower.includes(feature) && !lower.includes(`${feature}=()`)) {
            f.push({ id: `pp-${feature}-enabled`, category: "Security Headers", severity: "low", status: "warn", title: `Permissions-Policy does not restrict ${feature}`, evidence: `The ${feature} feature is not explicitly disabled.`, recommendation: `Add ${feature}=() to restrict access to this feature.` });
          }
        }
        return f;
      },
    },
    {
      key: "cross-origin-opener-policy",
      name: "Cross-Origin-Opener-Policy",
      missingSeverity: "info",
      analyze: () => [],
    },
    {
      key: "cross-origin-resource-policy",
      name: "Cross-Origin-Resource-Policy",
      missingSeverity: "info",
      analyze: () => [],
    },
    {
      key: "x-xss-protection",
      name: "X-XSS-Protection",
      missingSeverity: "info" as const,
      analyze(value) {
        if (value.trim() === "0") return [];
        return [{ id: "xss-protection-deprecated", category: "Security Headers", severity: "info", status: "info", title: "X-XSS-Protection header is set", evidence: `Value: ${value}. This header is deprecated in modern browsers.`, recommendation: "Remove X-XSS-Protection and rely on Content-Security-Policy instead." }];
      },
    },
  ];

  for (const check of headerChecks) {
    const value = response.headers.get(check.key);
    if (!value) {
      if (check.key === "strict-transport-security" && url.protocol !== "https:") continue;
      findings.push({
        id: `header-${check.key}`,
        category: "Security Headers",
        severity: check.missingSeverity,
        status: check.missingSeverity === "info" ? "info" : "fail",
        title: `${check.name} is missing`,
        evidence: `No ${check.name} response header was observed.`,
        recommendation: `Configure ${check.name} deliberately for this application.`,
      });
      continue;
    }

    findings.push({
      id: `header-${check.key}`,
      category: "Security Headers",
      severity: "info",
      status: "pass",
      title: `${check.name} is present`,
      evidence: value.slice(0, 500),
      recommendation: "Keep the policy reviewed and aligned with the application.",
    });

    if (check.analyze) {
      const extra = check.analyze(value);
      findings.push(...extra);
    }
  }

  return findings;
}
