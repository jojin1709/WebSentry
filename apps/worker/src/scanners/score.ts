import type { Finding, Severity } from "../types";

const weights: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };

export function calculateScore(findings: Finding[], https: boolean): number {
  let penalty = https ? 0 : 15;
  for (const finding of findings) {
    if (finding.status === "pass" || finding.status === "info") continue;
    penalty += weights[finding.severity];
  }
  return Math.max(0, Math.min(100, 100 - Math.round(penalty)));
}

export function countSeverities(findings: Finding[]): Record<Severity, number> {
  return findings.reduce((acc, f) => { acc[f.severity] += 1; return acc; }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>);
}
