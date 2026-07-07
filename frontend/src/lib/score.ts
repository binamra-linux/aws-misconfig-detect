import type { Finding, Severity } from "@/lib/api"

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
}

export interface SecurityScore {
  score: number
  label: string
  color: string
}

/**
 * A simple severity-weighted heuristic, not a literal "% of checks passed"
 * (we don't track how many checks were attempted per resource) -- deducts
 * points per finding, weighted by severity, floored at 0.
 *
 * The authoritative score now comes from the API (backend/scoring.py mirrors
 * this exact formula) so the live UI and scan history never disagree about
 * what "the score" is for a given scan. This client-side copy is kept only
 * as a reference/fallback -- prefer `data.score` from the API where available.
 */
export function computeSecurityScore(findings: Finding[]): SecurityScore {
  const deduction = findings.reduce((total, f) => total + (SEVERITY_WEIGHT[f.severity] ?? 0), 0)
  const score = Math.max(0, Math.round(100 - deduction))

  if (score >= 90) return { score, label: "Secure", color: "var(--primary)" }
  if (score >= 60) return { score, label: "Needs Attention", color: "var(--severity-medium)" }
  return { score, label: "At Risk", color: "var(--severity-critical)" }
}

export function getScoreColor(label: string): string {
  if (label === "Secure") return "var(--primary)"
  if (label === "Needs Attention") return "var(--severity-medium)"
  return "var(--severity-critical)"
}
