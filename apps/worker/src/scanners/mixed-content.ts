import type { Finding } from "../types";

export function scanMixedContent(html: string, finalUrl: URL): Finding[] {
  const findings: Finding[] = [];
  if (finalUrl.protocol !== "https:") return findings;

  const httpPattern = /(?:src|href|action|poster|data)=["']http:\/\/[^"']+/gi;
  const matches = html.match(httpPattern) || [];
  const unique = [...new Set(matches.map((m) => {
    const urlMatch = m.match(/["']([^"']+)/);
    return urlMatch ? urlMatch[1] : m;
  }))];

  if (unique.length > 0) {
    findings.push({
      id: "mixed-content",
      category: "Mixed Content",
      severity: "medium",
      status: "warn",
      title: "Mixed content detected on HTTPS page",
      evidence: `Found ${unique.length} HTTP resource(s) loaded on an HTTPS page: ${unique.slice(0, 5).join(", ")}${unique.length > 5 ? ` (+${unique.length - 5} more)` : ""}`,
      recommendation: "Change all resource URLs to use HTTPS. Mixed content can be blocked by browsers and weakens the security of the page.",
    });
  }

  const scriptPattern = /<script[^>]+src=["']http:\/\/[^"']+/gi;
  const scripts = html.match(scriptPattern) || [];
  if (scripts.length > 0) {
    findings.push({
      id: "mixed-content-script",
      category: "Mixed Content",
      severity: "high",
      status: "fail",
      title: "Mixed active content (scripts) on HTTPS page",
      evidence: `Found ${scripts.length} HTTP script(s) loaded on an HTTPS page.`,
      recommendation: "Immediately change script sources to HTTPS. Active mixed content is blocked by modern browsers and can enable man-in-the-middle attacks.",
    });
  }

  return findings;
}
