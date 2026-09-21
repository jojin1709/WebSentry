const DOH = "https://1.1.1.1/dns-query";

async function resolveDoh(host: string, type: string): Promise<string[]> {
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60 },
    });
    if (!res.ok) return [];
    const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
    if (!data.Answer) return [];
    const typeNum = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CAA: 257 }[type] ?? 0;
    return data.Answer.filter((a) => a.type === typeNum).map((a) => a.data);
  } catch {
    return [];
  }
}

async function resolveTxt(host: string): Promise<string[]> {
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(host)}&type=TXT`, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60 },
    });
    if (!res.ok) return [];
    const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
    if (!data.Answer) return [];
    return data.Answer.filter((a) => a.type === 16).map((a) => {
      if (a.data.startsWith('"') && a.data.endsWith('"')) return a.data.slice(1, -1);
      return a.data;
    });
  } catch {
    return [];
  }
}

function analyzeSpf(records: string[]): { found: boolean; policy: string | null } {
  for (const rec of records) {
    if (rec.toLowerCase().startsWith("v=spf1")) {
      let policy: string | null = null;
      if (rec.includes("-all")) policy = "hard-fail";
      else if (rec.includes("~all")) policy = "soft-fail";
      else if (rec.includes("?all")) policy = "neutral";
      else if (rec.includes("+all")) policy = "pass-all";
      return { found: true, policy };
    }
  }
  return { found: false, policy: null };
}

function analyzeDmarc(records: string[]): { found: boolean; policy: string | null; rua: string | null } {
  for (const rec of records) {
    if (rec.toLowerCase().startsWith("v=dmarc1")) {
      let policy: string | null = null;
      let rua: string | null = null;
      const parts = rec.split(";").map((s) => s.trim());
      for (const part of parts) {
        if (part.toLowerCase().startsWith("p=")) policy = part.split("=")[1];
        if (part.toLowerCase().startsWith("rua=")) rua = part.split("=").slice(1).join("=");
      }
      return { found: true, policy, rua };
    }
  }
  return { found: false, policy: null, rua: null };
}

function analyzeCaa(records: string[]): string[] {
  return records.map((r) => {
    try {
      const match = r.match(/^(\d+)\s+(issue|issuewild|iodef)\s+"(.+?)"/);
      if (match) {
        return `${match[2]}: ${match[3]}`;
      }
      return r;
    } catch {
      return r;
    }
  });
}

export interface DnsResult {
  A: string[];
  AAAA: string[];
  MX: string[];
  NS: string[];
  TXT: string[];
  CAA: string[];
  spf: { found: boolean; policy: string | null };
  dmarc: { found: boolean; policy: string | null; rua: string | null };
}

export async function scanDns(host: string): Promise<DnsResult> {
  const [A, AAAA, MX, NS, txtRecords, caaRaw] = await Promise.all([
    resolveDoh(host, "A"),
    resolveDoh(host, "AAAA"),
    resolveDoh(host, "MX"),
    resolveDoh(host, "NS"),
    resolveTxt(host),
    resolveDoh(host, "CAA"),
  ]);

  const spf = analyzeSpf(txtRecords);
  const dmarcHost = `_dmarc.${host}`;
  const dmarcTxt = await resolveTxt(dmarcHost);
  const dmarc = analyzeDmarc(dmarcTxt);
  const CAA = analyzeCaa(caaRaw);

  return { A, AAAA, MX, NS, TXT: txtRecords, CAA, spf, dmarc };
}

export function dnsFindings(dns: DnsResult): import("../types").Finding[] {
  const findings: import("../types").Finding[] = [];

  if (!dns.spf.found) {
    findings.push({
      id: "dns-no-spf",
      category: "Email Security",
      severity: "high",
      status: "fail",
      title: "No SPF record found",
      evidence: "No TXT record starting with v=spf1 was found for this domain.",
      recommendation: "Add an SPF record to prevent email spoofing. Example: v=spf1 include:_spf.google.com -all",
    });
  } else if (dns.spf.policy === "pass-all" || dns.spf.policy === "neutral") {
    findings.push({
      id: "dns-weak-spf",
      category: "Email Security",
      severity: "medium",
      status: "warn",
      title: "SPF policy is too permissive",
      evidence: `SPF uses ?all (neutral) or +all (pass), which does not effectively reject unauthorized senders.`,
      recommendation: "Use -all (hard fail) or ~all (soft fail) to reject or flag unauthorized email senders.",
    });
  } else if (dns.spf.policy) {
    findings.push({
      id: "dns-spf-ok",
      category: "Email Security",
      severity: "info",
      status: "pass",
      title: "SPF record found",
      evidence: `SPF policy: ${dns.spf.policy}`,
      recommendation: "Keep SPF record under review as email infrastructure changes.",
    });
  }

  if (!dns.dmarc.found) {
    findings.push({
      id: "dns-no-dmarc",
      category: "Email Security",
      severity: "high",
      status: "fail",
      title: "No DMARC record found",
      evidence: "No _dmarc TXT record was found for this domain.",
      recommendation: "Add a DMARC record. Example: v=dmarc1; p=quarantine; rua=mailto:dmarc@domain.com",
    });
  } else {
    if (dns.dmarc.policy === "none") {
      findings.push({
        id: "dns-dmarc-none",
        category: "Email Security",
        severity: "medium",
        status: "warn",
        title: "DMARC policy is set to none",
        evidence: "DMARC p=none only monitors but does not enforce.",
        recommendation: "Move to p=quarantine or p=reject after reviewing DMARC aggregate reports.",
      });
    } else if (dns.dmarc.policy === "quarantine" || dns.dmarc.policy === "reject") {
      findings.push({
        id: "dns-dmarc-enforced",
        category: "Email Security",
        severity: "info",
        status: "pass",
        title: "DMARC policy is enforced",
        evidence: `DMARC policy: p=${dns.dmarc.policy}`,
        recommendation: "Keep DMARC policy under review.",
      });
    }
    if (!dns.dmarc.rua) {
      findings.push({
        id: "dns-dmarc-no-rua",
        category: "Email Security",
        severity: "low",
        status: "warn",
        title: "DMARC has no aggregate reporting (rua)",
        evidence: "DMARC record does not include a rua= directive for aggregate reports.",
        recommendation: "Add rua=mailto:dmarc-reports@domain.com for visibility into email authentication.",
      });
    }
  }

  if (dns.MX.length === 0) {
    findings.push({
      id: "dns-no-mx",
      category: "Email Security",
      severity: "low",
      status: "info",
      title: "No MX records found",
      evidence: "No MX records were found. This domain may not receive email.",
      recommendation: "If this domain sends email, ensure MX and related records are properly configured.",
    });
  }

  if (dns.CAA.length > 0) {
    findings.push({
      id: "dns-caa-found",
      category: "Email Security",
      severity: "info",
      status: "pass",
      title: "CAA records found",
      evidence: `CAA records: ${dns.CAA.join("; ")}`,
      recommendation: "CAA records restrict which Certificate Authorities can issue certificates.",
    });
  }

  return findings;
}
