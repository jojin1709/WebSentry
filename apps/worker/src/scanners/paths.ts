import type { Finding, ExposedPath } from "../types";

const SENSITIVE_PATHS = [
  { path: "/.git/HEAD", title: "Git repository exposed", severity: "critical" as const, desc: "The .git directory is accessible, leaking source code history." },
  { path: "/.git/config", title: "Git config exposed", severity: "critical" as const, desc: "Git configuration file is publicly accessible." },
  { path: "/.env", title: ".env file exposed", severity: "critical" as const, desc: "Environment file containing secrets is publicly accessible." },
  { path: "/.env.local", title: ".env.local exposed", severity: "critical" as const, desc: "Local environment file is publicly accessible." },
  { path: "/.env.production", title: ".env.production exposed", severity: "critical" as const, desc: "Production environment file is publicly accessible." },
  { path: "/.env.backup", title: ".env backup exposed", severity: "critical" as const, desc: "Backup environment file is publicly accessible." },
  { path: "/.DS_Store", title: ".DS_Store exposed", severity: "medium" as const, desc: "macOS directory metadata file leaks file structure." },
  { path: "/wp-config.php.bak", title: "WordPress config backup", severity: "critical" as const, desc: "WordPress configuration backup is accessible, may contain database credentials." },
  { path: "/wp-config.php~", title: "WordPress config backup", severity: "critical" as const, desc: "WordPress configuration temp file is accessible." },
  { path: "/wp-config.php.old", title: "WordPress config backup", severity: "critical" as const, desc: "WordPress old config file is accessible." },
  { path: "/server-status", title: "Apache server-status exposed", severity: "high" as const, desc: "Apache mod_status page is publicly accessible." },
  { path: "/server-info", title: "Apache server-info exposed", severity: "high" as const, desc: "Apache mod_info page is publicly accessible." },
  { path: "/phpinfo.php", title: "PHP info page exposed", severity: "high" as const, desc: "phpinfo() page leaks server configuration details." },
  { path: "/info.php", title: "PHP info page exposed", severity: "high" as const, desc: "phpinfo() page leaks server configuration details." },
  { path: "/debug", title: "Debug endpoint exposed", severity: "medium" as const, desc: "A debug endpoint is publicly accessible." },
  { path: "/debug/pprof/", title: "Go pprof exposed", severity: "high" as const, desc: "Go pprof profiling endpoint is publicly accessible." },
  { path: "/admin", title: "Admin panel path found", severity: "low" as const, desc: "An /admin path responded, which may indicate an admin panel." },
  { path: "/administrator", title: "Admin panel path found", severity: "low" as const, desc: "An /administrator path responded, which may indicate an admin panel." },
  { path: "/backup", title: "Backup directory found", severity: "medium" as const, desc: "A /backup path responded, which may expose data." },
  { path: "/dump.sql", title: "SQL dump exposed", severity: "critical" as const, desc: "A SQL dump file is publicly accessible." },
  { path: "/database.sql", title: "SQL dump exposed", severity: "critical" as const, desc: "A SQL dump file is publicly accessible." },
  { path: "/.htaccess", title: ".htaccess exposed", severity: "high" as const, desc: "Apache .htaccess file is publicly accessible." },
  { path: "/.htpasswd", title: ".htpasswd exposed", severity: "critical" as const, desc: "Apache password file is publicly accessible." },
  { path: "/crossdomain.xml", title: "crossdomain.xml found", severity: "low" as const, desc: "Flash crossdomain.xml may grant overly broad cross-origin access." },
  { path: "/clientaccesspolicy.xml", title: "Silverlight policy found", severity: "low" as const, desc: "Silverlight client access policy may grant overly broad cross-origin access." },
  { path: "/elmah.axd", title: "ELMAH error log exposed", severity: "high" as const, desc: "ASP.NET ELMAH error log is publicly accessible." },
  { path: "/trace.axd", title: "ASP.NET trace exposed", severity: "high" as const, desc: "ASP.NET trace handler is publicly accessible." },
  { path: "/web.config", title: "web.config exposed", severity: "high" as const, desc: "ASP.NET web.config file is publicly accessible." },
  { path: "/config.json", title: "config.json exposed", severity: "high" as const, desc: "Configuration JSON file is publicly accessible." },
  { path: "/config.yml", title: "config.yml exposed", severity: "high" as const, desc: "Configuration YAML file is publicly accessible." },
  { path: "/config.xml", title: "config.xml exposed", severity: "high" as const, desc: "Configuration XML file is publicly accessible." },
  { path: "/composer.json", title: "composer.json exposed", severity: "medium" as const, desc: "PHP dependency file may reveal package versions." },
  { path: "/package.json", title: "package.json exposed", severity: "medium" as const, desc: "Node.js dependency file may reveal package versions." },
  { path: "/Gemfile", title: "Gemfile exposed", severity: "medium" as const, desc: "Ruby dependency file may reveal package versions." },
  { path: "/.ssh/", title: "SSH directory found", severity: "critical" as const, desc: "An .ssh directory responded, which is a critical security issue." },
  { path: "/wp-login.php", title: "WordPress login page found", severity: "info" as const, desc: "WordPress login page is accessible." },
  { path: "/xmlrpc.php", title: "XML-RPC exposed", severity: "medium" as const, desc: "WordPress XML-RPC can be used for brute force and DDoS attacks." },
];

const BLOCKED_PATHS = [
  "/.git/config",
  "/.git/HEAD",
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.backup",
  "/.htpasswd",
  "/dump.sql",
  "/database.sql",
  "/.ssh/",
];

export async function scanPaths(
  baseUrl: URL,
  timeoutMs: number,
  maxBytes: number,
): Promise<{ paths: ExposedPath[]; findings: Finding[] }> {
  const exposed: ExposedPath[] = [];
  const findings: Finding[] = [];
  const origin = `${baseUrl.protocol}//${baseUrl.host}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const results = await Promise.allSettled(
      SENSITIVE_PATHS.map(async (item) => {
        try {
          const res = await fetch(`${origin}${item.path}`, {
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(timeoutMs),
            headers: {
              "User-Agent": "WebSentry/1.0 (+https://websentry.example)",
              "Accept": "*/*",
            },
            cf: { cacheTtl: 0 },
          });
          if (res.status === 200 || res.status === 403) {
            return { ...item, status: res.status };
          }
          return null;
        } catch {
          return null;
        }
      }),
    );

    for (const r of results) {
      if (r.status === "fulfilled" && r.value) {
        const item = r.value;
        const ep: ExposedPath = {
          path: item.path,
          status: item.status,
          severity: item.severity,
          title: item.title,
          description: item.desc,
        };
        exposed.push(ep);

        const isHighRisk = BLOCKED_PATHS.includes(item.path);
        findings.push({
          id: `path-${item.path.replace(/[^a-z0-9]/gi, "-")}`,
          category: "Exposed Paths",
          severity: isHighRisk ? "critical" : item.severity,
          status: "fail",
          title: item.title,
          evidence: `${item.path} returned HTTP ${item.status}. ${item.desc}`,
          recommendation: isHighRisk
            ? `Immediately block public access to ${item.path}. This path exposes sensitive data.`
            : `Review whether ${item.path} should be publicly accessible and restrict access if not needed.`,
        });
      }
    }
  } finally {
    clearTimeout(timer);
  }

  return { paths: exposed, findings };
}
