import type { Finding } from "../types";

const MAP_PATHS = [
  "/main.js.map",
  "/app.js.map",
  "/bundle.js.map",
  "/index.js.map",
  "/vendor.js.map",
  "/chunk.js.map",
  "/assets/js/",
  "/_next/static/",
  "/build/static/",
  "/dist/",
  "/out/",
  "/public/assets/",
];

const DEBUG_PATHS = [
  "/__debug/",
  "/debug/default/view",
  "/debug/vars",
  "/_debug/",
  "/debug/toolbar/",
  "/.well-known/debug/",
  "/actuator",
  "/actuator/env",
  "/actuator/health",
  "/actuator/info",
  "/metrics",
  "/prometheus",
  "/debug/pprof/goroutine",
  "/debug/pprof/heap",
];

const INFO_LEAK_PATHS = [
  "/readme.md",
  "/README.md",
  "/CHANGELOG.md",
  "/LICENSE",
  "/CONTRIBUTING.md",
  "/TODO.md",
  "/.editorconfig",
  "/.babelrc",
  "/babel.config.js",
  "/webpack.config.js",
  "/vite.config.js",
  "/tsconfig.json",
  "/jsconfig.json",
  "/docker-compose.yml",
  "/docker-compose.yaml",
  "/Dockerfile",
  "/.dockerignore",
  "/package-lock.json",
  "/yarn.lock",
  "/pnpm-lock.yaml",
  "/Gemfile.lock",
  "/composer.lock",
  "/requirements.txt",
  "/Pipfile.lock",
  "/go.sum",
];

async function probePath(origin: string, path: string, timeoutMs: number): Promise<boolean> {
  try {
    const res = await fetch(`${origin}${path}`, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "User-Agent": "WebSentry/1.0" },
      cf: { cacheTtl: 0 },
    });
    return res.status === 200 || res.status === 403;
  } catch {
    return false;
  }
}

export async function scanSourceExposure(
  baseUrl: URL,
  timeoutMs: number,
  html: string,
): Promise<{ findings: Finding[] }> {
  const findings: Finding[] = [];
  const origin = `${baseUrl.protocol}//${baseUrl.host}`;

  const bodyLower = html.toLowerCase();
  const versionPatterns = [
    { pattern: /x-powered-by:\s*(.+)/i, name: "X-Powered-By (in HTML)" },
    { pattern: /powered by (apache|nginx|express|php|asp\.net|tomcat|django|rails)/i, name: "Server mention in HTML" },
  ];

  for (const { pattern, name } of versionPatterns) {
    const match = html.match(pattern);
    if (match) {
      findings.push({
        id: `leak-${name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`,
        category: "Information Leakage",
        severity: "low",
        status: "info",
        title: `${name} detected`,
        evidence: match[0].slice(0, 200),
        recommendation: "Consider removing technology version information from public-facing content.",
      });
    }
  }

  const errorIndicators = ["stack trace", "traceback", "exception in", "fatal error", "debug mode", "debug toolbar"];
  for (const indicator of errorIndicators) {
    if (bodyLower.includes(indicator)) {
      findings.push({
        id: "leak-error-info",
        category: "Information Leakage",
        severity: "medium",
        status: "fail",
        title: "Error/debug information exposed in page content",
        evidence: `Found "${indicator}" in the page body.`,
        recommendation: "Remove debug information and stack traces from production responses.",
      });
      break;
    }
  }

  const batchSize = 8;
  const allPaths = [...MAP_PATHS, ...DEBUG_PATHS, ...INFO_LEAK_PATHS];

  for (let i = 0; i < allPaths.length; i += batchSize) {
    const batch = allPaths.slice(i, i + batchSize);
    const results = await Promise.allSettled(batch.map((p) => probePath(origin, p, timeoutMs)));

    for (let j = 0; j < results.length; j++) {
      if (results[j].status === "fulfilled" && results[j].value) {
        const path = batch[j];
        const isMap = path.endsWith(".map") || path.includes(".map");
        const isDebug = DEBUG_PATHS.includes(path);
        const isLock = path.endsWith("lock.json") || path.endsWith("lock.yaml") || path.endsWith("lock.txt") || path.endsWith("lock") || path.includes("lock-");

        let severity: "critical" | "high" | "medium" | "low" = "low";
        let title = "Sensitive file accessible";
        let desc = `${path} is publicly accessible.`;

        if (isMap) {
          severity = "medium";
          title = "Source map file exposed";
          desc = `JavaScript source map ${path} is publicly accessible, revealing original source code.`;
        } else if (isDebug) {
          severity = "high";
          title = "Debug endpoint exposed";
          desc = `Debug endpoint ${path} is publicly accessible.`;
        } else if (isLock) {
          severity = "medium";
          title = "Dependency lock file exposed";
          desc = `Lock file ${path} is publicly accessible, revealing exact dependency versions.`;
        } else if (path.includes(".env") || path.includes("config")) {
          severity = "critical";
          title = "Configuration file exposed";
          desc = `Configuration file ${path} is publicly accessible.`;
        }

        findings.push({
          id: `source-${path.replace(/[^a-z0-9]/gi, "-")}`,
          category: "Information Leakage",
          severity,
          status: "fail",
          title,
          evidence: desc,
          recommendation: `Block public access to ${path}.`,
        });
      }
    }
  }

  return { findings };
}
