export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
export type CheckStatus = "PASS" | "FAIL"

export interface Finding {
  id: number
  resource_id: string
  resource_type: string
  check_type: string
  severity: Severity
  description: string
  detail: Record<string, unknown>
  region: string | null
}

export interface CheckResultItem {
  id: number
  resource_id: string
  resource_type: string
  check_type: string
  status: CheckStatus
  severity: Severity | null
  description: string
  detail: Record<string, unknown>
  region: string | null
}

export interface ScoreInfo {
  score: number
  label: string
}

export interface FindingsResponse {
  scan_id: number
  scanned_at: string | null
  score: ScoreInfo
  findings: Finding[]
}

export interface ResourcesResponse {
  scan_id: number
  scanned_at: string | null
  checks: CheckResultItem[]
}

export interface HistoryRecord {
  scanned_at: string
  total_findings: number
  severity_counts: Record<Severity, number>
  score: number
  label: string
}

export interface HistoryResponse {
  scans: HistoryRecord[]
}

export interface ScheduleInfo {
  enabled: boolean
  cron: string | null
  next_run: string | null
  alerts_configured: boolean
  alert_recipients: string[]
}

export interface ConfigInfo {
  aws_region: string
  aws_regions: string
  aws_profile: string
  groq_model: string
  iam_unused_key_days: number
  remediation_enabled: boolean
  schedule: ScheduleInfo
}

export interface ExplanationResponse {
  explanation: string
}

export interface AuthStatus {
  needs_setup: boolean
  user: string | null
}

export interface RemediationInfo {
  available: boolean
  enabled: boolean
  description: string | null
}

/** Thrown on a 401 so callers can distinguish "logged out" from any other failure. */
export class UnauthorizedError extends Error {
  constructor(message = "Not authenticated.") {
    super(message)
    this.name = "UnauthorizedError"
  }
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options)
  if (!res.ok) {
    let message = res.statusText
    try {
      const body = await res.json()
      message = body.detail ?? message
    } catch {
      // response body wasn't JSON -- fall back to statusText
    }
    if (res.status === 401) throw new UnauthorizedError(message)
    throw new Error(message)
  }
  return res.json()
}

function post<T>(url: string, body?: unknown): Promise<T> {
  return request<T>(url, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
}

export function getAuthStatus(): Promise<AuthStatus> {
  return request<AuthStatus>("/api/auth/status")
}

export function login(username: string, password: string): Promise<{ user: string }> {
  return post<{ user: string }>("/api/auth/login", { username, password })
}

export function registerUser(username: string, password: string): Promise<{ user: string }> {
  return post<{ user: string }>("/api/auth/register", { username, password })
}

export function logout(): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>("/api/auth/logout")
}

export function runScan(): Promise<FindingsResponse> {
  return request<FindingsResponse>("/api/scan", { method: "POST" })
}

export function resetApp(): Promise<FindingsResponse> {
  return request<FindingsResponse>("/api/reset", { method: "POST" })
}

export function getRemediationInfo(scanId: number, findingId: number): Promise<RemediationInfo> {
  return request<RemediationInfo>(`/api/findings/${scanId}/${findingId}/remediation`)
}

export function remediateFinding(
  scanId: number,
  findingId: number,
): Promise<{ ok: boolean; message: string }> {
  return post<{ ok: boolean; message: string }>(`/api/findings/${scanId}/${findingId}/remediate`)
}

export function getFindings(): Promise<FindingsResponse> {
  return request<FindingsResponse>("/api/findings")
}

export function getResources(): Promise<ResourcesResponse> {
  return request<ResourcesResponse>("/api/resources")
}

export function getHistory(): Promise<HistoryResponse> {
  return request<HistoryResponse>("/api/history")
}

export function getConfig(): Promise<ConfigInfo> {
  return request<ConfigInfo>("/api/config")
}

export function updateConfig(iamUnusedKeyDays: number): Promise<ConfigInfo> {
  return request<ConfigInfo>("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iam_unused_key_days: iamUnusedKeyDays }),
  })
}

export function explainFinding(scanId: number, findingId: number): Promise<ExplanationResponse> {
  return request<ExplanationResponse>(`/api/findings/${scanId}/${findingId}/explain`, {
    method: "POST",
  })
}
