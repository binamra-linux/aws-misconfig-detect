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

export interface ConfigInfo {
  aws_region: string
  aws_profile: string
  groq_model: string
  iam_unused_key_days: number
}

export interface ExplanationResponse {
  explanation: string
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
    throw new Error(message)
  }
  return res.json()
}

export function runScan(): Promise<FindingsResponse> {
  return request<FindingsResponse>("/api/scan", { method: "POST" })
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
