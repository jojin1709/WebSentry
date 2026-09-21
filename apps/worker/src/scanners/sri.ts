import type { Finding } from "../types";

export interface SriResult {
  totalScripts: number;
  externalScripts: number;
  scriptsWithIntegrity: number;
  totalLinks: number;
  externalLinks: number;
  linksWithIntegrity: number;
}

export function scanSri(html: string): { sri: SriResult; findings: Finding[] } {
  const findings: Finding[] = [];

  const scriptTags = html.match(/<script[^>]*>/gi) || [];
  const externalScripts = scriptTags.filter((s) => /src=["'][^"']+["']/i.test(s));
  const scriptsWithIntegrity = externalScripts.filter((s) => /integrity=["'][^"']+["']/i.test(s));

  const linkTags = html.match(/<link[^>]*>/gi) || [];
  const externalLinks = linkTags.filter((l) => /href=["'][^"']+["']/i.test(l) && /rel=["'](stylesheet|preload|preconnect)/i.test(l));
  const linksWithIntegrity = externalLinks.filter((l) => /integrity=["'][^"']+["']/i.test(l));

  const sri: SriResult = {
    totalScripts: scriptTags.length,
    externalScripts: externalScripts.length,
    scriptsWithIntegrity: scriptsWithIntegrity.length,
    totalLinks: linkTags.length,
    externalLinks: externalLinks.length,
    linksWithIntegrity: linksWithIntegrity.length,
  };

  const missingScripts = externalScripts.length - scriptsWithIntegrity.length;
  if (externalScripts.length > 0 && missingScripts > 0) {
    const srcs = externalScripts.filter((s) => !/integrity=/i.test(s)).map((s) => {
      const m = s.match(/src=["']([^"']+)/i);
      return m ? m[1] : "unknown";
    });
    findings.push({
      id: "sri-missing-scripts",
      category: "Subresource Integrity",
      severity: missingScripts >= 3 ? "medium" : "low",
      status: "warn",
      title: `${missingScripts} external script(s) missing SRI`,
      evidence: `Scripts without integrity: ${srcs.slice(0, 3).join(", ")}${srcs.length > 3 ? ` (+${srcs.length - 3} more)` : ""}`,
      recommendation: "Add integrity attributes to external scripts to prevent tampering via CDN compromises.",
    });
  }

  const missingLinks = externalLinks.length - linksWithIntegrity.length;
  if (externalLinks.length > 0 && missingLinks > 0) {
    findings.push({
      id: "sri-missing-links",
      category: "Subresource Integrity",
      severity: "low",
      status: "warn",
      title: `${missingLinks} external stylesheet(s) missing SRI`,
      evidence: `${missingLinks} of ${externalLinks.length} external stylesheets lack integrity attributes.`,
      recommendation: "Add integrity attributes to external stylesheets loaded from third-party CDNs.",
    });
  }

  if (externalScripts.length > 0 && scriptsWithIntegrity.length === externalScripts.length) {
    findings.push({
      id: "sri-all-scripts",
      category: "Subresource Integrity",
      severity: "info",
      status: "pass",
      title: "All external scripts use SRI",
      evidence: `${scriptsWithIntegrity.length} of ${externalScripts.length} scripts have integrity attributes.`,
      recommendation: "Maintain SRI coverage as new scripts are added.",
    });
  }

  return { sri, findings };
}
