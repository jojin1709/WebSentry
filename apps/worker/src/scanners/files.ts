import { fetchText } from "../lib/fetch-safe";

export async function scanRobots(base: URL, timeoutMs: number, maxBytes: number) {
  const url = new URL("/robots.txt", base);
  try {
    const { response, text } = await fetchText(url, timeoutMs, maxBytes);
    if (!response.ok) return { found: false, sitemapCount: 0, disallowCount: 0 };
    const lines = text.split(/\r?\n/);
    return { found: true, sitemapCount: lines.filter((x) => /^\s*sitemap\s*:/i.test(x)).length, disallowCount: lines.filter((x) => /^\s*disallow\s*:/i.test(x)).length };
  } catch { return { found: false, sitemapCount: 0, disallowCount: 0 }; }
}

export async function scanSecurityTxt(base: URL, timeoutMs: number, maxBytes: number) {
  const url = new URL("/.well-known/security.txt", base);
  try {
    const { response, text } = await fetchText(url, timeoutMs, maxBytes);
    if (!response.ok) return { found: false, contactCount: 0, expires: null };
    const contacts = text.split(/\r?\n/).filter((x) => /^\s*contact\s*:/i.test(x)).length;
    const expires = text.split(/\r?\n/).find((x) => /^\s*expires\s*:/i.test(x))?.split(":").slice(1).join(":").trim() ?? null;
    return { found: true, contactCount: contacts, expires };
  } catch { return { found: false, contactCount: 0, expires: null }; }
}
