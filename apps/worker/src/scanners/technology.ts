export function detectTechnologies(html: string, headers: Headers): string[] {
  const source = html.toLowerCase();
  const found = new Set<string>();
  const server = headers.get("server")?.toLowerCase() ?? "";
  const powered = headers.get("x-powered-by")?.toLowerCase() ?? "";
  if (source.includes("__next_data__") || source.includes("/_next/")) found.add("Next.js");
  if (source.includes("react") || source.includes("data-reactroot")) found.add("React");
  if (source.includes("wp-content/") || source.includes("wp-includes/")) found.add("WordPress");
  if (source.includes("ng-version") || source.includes("angular")) found.add("Angular");
  if (source.includes("vue") && source.includes("data-v-")) found.add("Vue.js");
  if (source.includes("__svelte") || source.includes("svelte")) found.add("Svelte");
  if (source.includes("cloudflare") || headers.has("cf-ray")) found.add("Cloudflare");
  if (server.includes("nginx")) found.add("Nginx");
  if (server.includes("apache")) found.add("Apache");
  if (powered.includes("express")) found.add("Express");
  if (source.includes("googletagmanager.com") || source.includes("google-analytics.com")) found.add("Google Analytics / Tag Manager");
  if (source.includes("tailwindcss")) found.add("Tailwind CSS");
  return [...found];
}
