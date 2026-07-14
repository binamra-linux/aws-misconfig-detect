import type { ReactNode } from "react"
import { BadgeCheck, Boxes, History as HistoryIcon, LayoutDashboard, ScanLine, ShieldAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { SeverityBadge } from "@/components/SeverityBadge"
import { Welcome } from "@/components/Welcome"
import { getScoreColor } from "@/lib/score"
import type { FindingsResponse, Severity } from "@/lib/api"
import type { Page } from "@/components/Sidebar"

const NAV_CARDS: { page: Page; label: string; description: string; icon: ReactNode }[] = [
  {
    page: "overview",
    label: "Overview",
    description: "Security score, severity breakdown, and resource coverage.",
    icon: <LayoutDashboard className="size-5" />,
  },
  {
    page: "findings",
    label: "Findings",
    description: "Browse and filter every issue, with AI-generated fixes.",
    icon: <ShieldAlert className="size-5" />,
  },
  {
    page: "resources",
    label: "Resources",
    description: "Every check performed across your account, pass and fail.",
    icon: <Boxes className="size-5" />,
  },
  {
    page: "compliance",
    label: "Compliance",
    description: "Findings mapped to CIS AWS Foundations Benchmark controls.",
    icon: <BadgeCheck className="size-5" />,
  },
  {
    page: "history",
    label: "History",
    description: "Track your security score and finding counts over time.",
    icon: <HistoryIcon className="size-5" />,
  },
]

const ATTENTION_SEVERITIES: Severity[] = ["CRITICAL", "HIGH"]

export function Home({
  data,
  isLoading,
  onScan,
  scanning,
  onNavigate,
}: {
  data?: FindingsResponse
  isLoading: boolean
  onScan: () => void
  scanning: boolean
  onNavigate: (page: Page) => void
}) {
  if (isLoading) {
    return (
      <div className="grid gap-6">
        <Skeleton className="h-28" />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
          <Skeleton className="h-28" />
        </div>
      </div>
    )
  }

  if (!data?.scanned_at) {
    return <Welcome onScan={onScan} scanning={scanning} />
  }

  const topFindings = data.findings.filter((f) => ATTENTION_SEVERITIES.includes(f.severity)).slice(0, 3)
  const scoreColor = getScoreColor(data.score.label)

  return (
    <div className="grid gap-6">
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-4 pt-6">
          <div>
            <p className="text-sm text-muted-foreground">
              Last scanned {new Date(data.scanned_at).toLocaleString()}
            </p>
            <p className="mt-1 text-2xl font-semibold" style={{ color: scoreColor }}>
              {data.score.score}%{" "}
              <span className="text-base font-normal text-muted-foreground">— {data.score.label}</span>
            </p>
          </div>
          <Button onClick={onScan} disabled={scanning}>
            <ScanLine className="size-4" />
            {scanning ? "Scanning..." : "Run New Scan"}
          </Button>
        </CardContent>
      </Card>

      {topFindings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Needs Attention</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {topFindings.map((f) => (
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
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {NAV_CARDS.map((c) => (
          <button key={c.page} onClick={() => onNavigate(c.page)} className="text-left">
            <Card className="h-full transition-colors hover:bg-accent/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-3">
                  <span className="flex size-9 items-center justify-center rounded-full bg-primary/10 text-primary">
                    {c.icon}
                  </span>
                  {c.label}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{c.description}</p>
              </CardContent>
            </Card>
          </button>
        ))}
      </div>
    </div>
  )
}
