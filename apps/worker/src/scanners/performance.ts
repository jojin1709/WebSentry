import type { Finding } from "../types";

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

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export function scanPerformance(html: string, responseTimeMs: number, contentType: string | null): { perf: PerformanceResult; findings: Finding[] } {
  const findings: Finding[] = [];

  const scriptTags = html.match(/<script[^>]*>/gi) || [];
  const externalScripts = scriptTags.filter((s) => /src=["'][^"']+["']/i.test(s));
  const inlineScripts = scriptTags.filter((s) => !/src=["'][^"']+["']/i.test(s));

  const linkTags = html.match(/<link[^>]*>/gi) || [];
  const stylesheets = linkTags.filter((l) => /rel=["']stylesheet/i.test(l));

  const imgTags = html.match(/<img[^>]*>/gi) || [];
  const iframeTags = html.match(/<iframe[^>]*>/gi) || [];
  const fontLinks = linkTags.filter((l) => /rel=["'](font|preload)["'][^>]*as=["']font/i.test(l));

  const resourceCount = {
    scripts: externalScripts.length + inlineScripts.length,
    stylesheets: stylesheets.length,
    images: imgTags.length,
    iframes: iframeTags.length,
    fonts: fontLinks.length,
    other: 0,
  };

  const headScripts = scriptTags.filter((s) => {
    const isHead = /<head[\s>]/i.test(html.split(/<script/i)[0] || "");
    return isHead && !/async|defer/i.test(s);
  });

  const renderBlockingScripts = headScripts.length;

  const renderBlockingStyles = stylesheets.filter((s) => {
    return !/media=["'](print|screen and \(min-width)/i.test(s);
  }).length;

  const bodySize = html.length;
  const perf: PerformanceResult = {
    responseTimeMs,
    pageSizeBytes: bodySize,
    pageSizeFormatted: formatBytes(bodySize),
    resourceCount,
    renderBlockingScripts,
    renderBlockingStyles,
    totalScriptSize: `${externalScripts.length} external, ${inlineScripts.length} inline`,
    totalStyleSize: `${stylesheets.length} stylesheet(s)`,
  };

  if (responseTimeMs > 3000) {
    findings.push({
      id: "perf-slow-response",
      category: "Performance",
      severity: "medium",
      status: "warn",
      title: "Slow server response time",
      evidence: `Server responded in ${responseTimeMs}ms. Recommended: under 200ms for TTFB.`,
      recommendation: "Optimize server-side rendering, use caching, or deploy closer to users.",
    });
  } else if (responseTimeMs > 1000) {
    findings.push({
      id: "perf-moderate-response",
      category: "Performance",
      severity: "low",
      status: "info",
      title: "Moderate server response time",
      evidence: `Server responded in ${responseTimeMs}ms.`,
      recommendation: "Consider optimizing server response time for better user experience.",
    });
  }

  if (bodySize > 3145728) {
    findings.push({
      id: "perf-large-page",
      category: "Performance",
      severity: "medium",
      status: "warn",
      title: "Page is very large",
      evidence: `Page size: ${formatBytes(bodySize)}. Recommended: under 3MB.`,
      recommendation: "Reduce page weight by optimizing content, compressing resources, and lazy-loading assets.",
    });
  }

  if (externalScripts.length > 15) {
    findings.push({
      id: "perf-many-scripts",
      category: "Performance",
      severity: "low",
      status: "warn",
      title: "Large number of external scripts",
      evidence: `${externalScripts.length} external script tags found.`,
      recommendation: "Bundle scripts and reduce the number of external requests.",
    });
  }

  if (renderBlockingScripts > 0) {
    findings.push({
      id: "perf-render-blocking-scripts",
      category: "Performance",
      severity: "medium",
      status: "warn",
      title: `${renderBlockingScripts} render-blocking script(s) in <head>`,
      evidence: `${renderBlockingScripts} script(s) in <head> without async or defer.`,
      recommendation: "Add async or defer attributes to non-critical scripts.",
    });
  }

  if (renderBlockingStyles > 3) {
    findings.push({
      id: "perf-render-blocking-styles",
      category: "Performance",
      severity: "low",
      status: "info",
      title: `${renderBlockingStyles} render-blocking stylesheet(s)`,
      evidence: `${renderBlockingStyles} stylesheet(s) loaded without media attribute optimization.`,
      recommendation: "Use media attributes to load non-critical CSS asynchronously.",
    });
  }

  if (imgTags.length > 0) {
    const lazyImages = imgTags.filter((i) => /loading=["']lazy/i.test(i)).length;
    if (lazyImages < imgTags.length * 0.5 && imgTags.length > 3) {
      findings.push({
        id: "perf-no-lazy-loading",
        category: "Performance",
        severity: "low",
        status: "info",
        title: "Limited lazy loading on images",
        evidence: `${lazyImages} of ${imgTags.length} images use loading="lazy".`,
        recommendation: "Add loading='lazy' to below-the-fold images to improve initial load.",
      });
    }
  }

  return { perf, findings };
}
