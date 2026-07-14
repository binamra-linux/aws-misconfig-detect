import type { ReactNode } from "react"
import { Boxes, ChartPie, Info, ListChecks, ShieldCheck } from "lucide-react"
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { SeverityBadge } from "@/components/SeverityBadge"
import { EmptyState } from "@/components/EmptyState"
import { getScoreColor } from "@/lib/score"
import type { FindingsResponse, Severity } from "@/lib/api"

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

const SEVERITY_CHART_COLORS: Record<Severity, string> = {
  CRITICAL: "var(--severity-critical)",
  HIGH: "var(--severity-high)",
  MEDIUM: "var(--severity-medium)",
  LOW: "var(--severity-low)",
}

function CardIcon({ children }: { children: ReactNode }) {
  return (
    <span className="flex size-8 items-center justify-center rounded-md bg-primary/10 text-primary">
      {children}
    </span>
  )
}

export function Overview({
  data,
  isLoading,
  onGoToFindings,
  onScan,
  scanning,
}: {
  data?: FindingsResponse
  isLoading: boolean
  onGoToFindings: () => void
  onScan: () => void
  scanning: boolean
}) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
      </div>
    )
  }

  const findings = data?.findings ?? []
  const total = findings.length

  if (total === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck className="size-6" />}
        title={data?.scanned_at ? "No issues found" : "No scan data yet"}
        description={
          data?.scanned_at
            ? "Your last scan didn't turn up any misconfigurations. Nice work — run another scan any time to re-check."
            : "Run a scan to see your security score, severity breakdown, and resource coverage here."
        }
        action={{ label: scanning ? "Scanning..." : "Run Scan", onClick: onScan }}
      />
    )
  }

  const severityCounts = SEVERITY_ORDER.reduce<Record<Severity, number>>(
    (acc, sev) => {
      acc[sev] = findings.filter((f) => f.severity === sev).length
      return acc
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  )

  const resourceTypeCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.resource_type] = (acc[f.resource_type] ?? 0) + 1
    return acc
  }, {})

  const chartData = SEVERITY_ORDER.filter((s) => severityCounts[s] > 0).map((s) => ({
    name: s,
    value: severityCounts[s],
  }))

  const score = data?.score ?? { score: 0, label: "Unknown" }
  const scoreColor = getScoreColor(score.label)
  const scoreChartData = [
    { name: "score", value: score.score },
    { name: "remaining", value: 100 - score.score },
  ]

  return (
    <div className="grid gap-6">
      {data?.scanned_at && (
        <p className="-mt-4 text-xs text-muted-foreground">
          Last scanned {new Date(data.scanned_at).toLocaleString()}
        </p>
      )}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              <CardIcon>
                <ShieldCheck className="size-4" />
              </CardIcon>
              Security Score
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="size-3.5 shrink-0 cursor-help text-muted-foreground" />
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-xs text-pretty">
                  Heuristic, not a literal pass rate: starts at 100 and deducts points per
                  finding (Critical −25, High −15, Medium −8, Low −3), floored at 0.
                </TooltipContent>
              </Tooltip>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <div className="relative h-28 w-28 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={scoreChartData}
                    dataKey="value"
                    innerRadius={35}
                    outerRadius={55}
                    startAngle={90}
                    endAngle={-270}
                    stroke="none"
                  >
                    <Cell fill={scoreColor} />
                    <Cell fill="var(--muted)" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-xl font-bold leading-none">{score.score}%</span>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold" style={{ color: scoreColor }}>
                {score.label}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Based on {total} finding(s) across your account
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              <CardIcon>
                <ChartPie className="size-4" />
              </CardIcon>
              Severity Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <div className="relative h-28 w-28 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={chartData} dataKey="value" nameKey="name" innerRadius={35} outerRadius={55} paddingAngle={2}>
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_CHART_COLORS[entry.name]} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-lg font-bold leading-none">{total}</span>
                <span className="text-[10px] text-muted-foreground">total</span>
              </div>
            </div>
            <div className="flex-1 space-y-2">
              {SEVERITY_ORDER.map((sev) => (
                <div key={sev} className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={sev} />
                  <span className="text-muted-foreground">
                    {severityCounts[sev]} ({total ? Math.round((severityCounts[sev] / total) * 100) : 0}%)
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              <CardIcon>
                <Boxes className="size-4" />
              </CardIcon>
              By Resource Type
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(resourceTypeCounts)
              .sort((a, b) => b[1] - a[1])
              .map(([type, count]) => (
                <div key={type} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{type}</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              <CardIcon>
                <ListChecks className="size-4" />
              </CardIcon>
              Total Findings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-4xl font-bold">{total}</div>
            <p className="mt-1 text-sm text-muted-foreground">
              across {Object.keys(resourceTypeCounts).length} resource type(s)
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-3">
            <CardIcon>
              <ListChecks className="size-4" />
            </CardIcon>
            Latest Findings
          </CardTitle>
          <button onClick={onGoToFindings} className="text-sm text-primary hover:underline">
            View all findings
          </button>
        </CardHeader>
        <CardContent className="space-y-3">
          {findings.slice(0, 5).map((f) => (
            <div
              key={f.id}
              className="flex items-center justify-between border-b border-border pb-3 last:border-0 last:pb-0"
            >
              <div className="space-y-0.5 pr-4">
                <p className="text-sm font-medium">{f.description}</p>
                <p className="text-xs text-muted-foreground">
                  {f.resource_type} · {f.resource_id}
                </p>
              </div>
              <SeverityBadge severity={f.severity} />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
