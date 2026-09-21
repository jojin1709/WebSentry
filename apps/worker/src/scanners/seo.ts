import type { Finding } from "../types";

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

export function scanSeo(html: string): { seo: SeoResult; findings: Finding[] } {
  const findings: Finding[] = [];

  const getMeta = (name: string): string | null => {
    const patterns = [
      new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)`, "i"),
      new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${name}["']`, "i"),
      new RegExp(`<meta[^>]+property=["']${name}["'][^>]+content=["']([^"']*)`, "i"),
      new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+property=["']${name}["']`, "i"),
    ];
    for (const p of patterns) {
      const m = html.match(p);
      if (m) return m[1];
    }
    return null;
  };

  const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : null;
  const description = getMeta("description");
  const canonicalMatch = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)/i);
  const canonical = canonicalMatch ? canonicalMatch[1] : null;
  const ogTitle = getMeta("og:title");
  const ogDescription = getMeta("og:description");
  const ogImage = getMeta("og:image");
  const robots = getMeta("robots");
  const viewport = getMeta("viewport");
  const langMatch = html.match(/<html[^>]+lang=["']([^"']*)/i);
  const lang = langMatch ? langMatch[1] : null;

  const headings: Record<string, number> = {};
  for (let i = 1; i <= 6; i++) {
    const h = html.match(new RegExp(`<h${i}[\\s>]`, "gi"));
    if (h) headings[`h${i}`] = h.length;
  }

  const seo: SeoResult = { title, description, canonical, ogTitle, ogDescription, ogImage, robots, viewport, lang, headings };

  if (!title) {
    findings.push({
      id: "seo-no-title",
      category: "SEO",
      severity: "medium",
      status: "fail",
      title: "Page is missing a <title> tag",
      evidence: "No <title> tag found in the HTML head.",
      recommendation: "Add a descriptive <title> tag. It is the most important on-page SEO element.",
    });
  } else if (title.length < 30) {
    findings.push({
      id: "seo-short-title",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: "Page title is very short",
      evidence: `Title: "${title}" (${title.length} characters). Recommended: 30-60 characters.`,
      recommendation: "Expand the title to 30-60 characters for better search engine visibility.",
    });
  } else if (title.length > 60) {
    findings.push({
      id: "seo-long-title",
      category: "SEO",
      severity: "info",
      status: "info",
      title: "Page title may be too long",
      evidence: `Title: "${title}" (${title.length} characters). May be truncated in search results.`,
      recommendation: "Keep titles under 60 characters to avoid truncation in search results.",
    });
  }

  if (!description) {
    findings.push({
      id: "seo-no-description",
      category: "SEO",
      severity: "medium",
      status: "fail",
      title: "Page is missing a meta description",
      evidence: "No meta description tag found.",
      recommendation: "Add a meta description of 120-160 characters to improve click-through rates from search results.",
    });
  } else if (description.length < 70) {
    findings.push({
      id: "seo-short-description",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: "Meta description is very short",
      evidence: `Description length: ${description.length} characters. Recommended: 120-160.`,
      recommendation: "Expand the meta description to 120-160 characters.",
    });
  }

  if (!canonical) {
    findings.push({
      id: "seo-no-canonical",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: "Page is missing a canonical URL",
      evidence: "No canonical link tag found.",
      recommendation: "Add a canonical URL to prevent duplicate content issues.",
    });
  }

  if (!ogTitle || !ogDescription) {
    findings.push({
      id: "seo-no-open-graph",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: "Open Graph tags are incomplete",
      evidence: `og:title: ${ogTitle ? "present" : "missing"}. og:description: ${ogDescription ? "present" : "missing"}.`,
      recommendation: "Add og:title, og:description, and og:image for better social media sharing.",
    });
  }

  if (!viewport) {
    findings.push({
      id: "seo-no-viewport",
      category: "SEO",
      severity: "medium",
      status: "fail",
      title: "Page is missing a viewport meta tag",
      evidence: "No viewport meta tag found.",
      recommendation: "Add <meta name='viewport' content='width=device-width, initial-scale=1'> for mobile responsiveness.",
    });
  }

  if (!lang) {
    findings.push({
      id: "seo-no-lang",
      category: "SEO",
      severity: "low",
      status: "info",
      title: "HTML lang attribute is missing",
      evidence: "The <html> tag does not have a lang attribute.",
      recommendation: "Add lang='en' (or appropriate language code) to the <html> tag for accessibility and SEO.",
    });
  }

  const h1Count = headings["h1"] || 0;
  if (h1Count === 0) {
    findings.push({
      id: "seo-no-h1",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: "Page is missing an H1 heading",
      evidence: "No <h1> tag found.",
      recommendation: "Add exactly one <h1> tag that describes the main content of the page.",
    });
  } else if (h1Count > 1) {
    findings.push({
      id: "seo-multiple-h1",
      category: "SEO",
      severity: "low",
      status: "warn",
      title: `Page has ${h1Count} H1 headings`,
      evidence: `Found ${h1Count} <h1> tags. Best practice is exactly one per page.`,
      recommendation: "Use only one <h1> tag per page for proper heading hierarchy.",
    });
  }

  return { seo, findings };
}
