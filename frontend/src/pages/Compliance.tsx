import { BadgeCheck } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { SeverityBadge } from "@/components/SeverityBadge"
import { EmptyState } from "@/components/EmptyState"
import { CIS_BENCHMARK_VERSION, getComplianceControl } from "@/lib/compliance"
import type { Finding, FindingsResponse } from "@/lib/api"

export function Compliance({ data, isLoading }: { data?: FindingsResponse; isLoading: boolean }) {
  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  const findings = data?.findings ?? []

  if (findings.length === 0) {
    return (
      <EmptyState
        icon={<BadgeCheck className="size-6" />}
        title={data?.scanned_at ? "No issues found" : "No findings yet"}
        description={
          data?.scanned_at
            ? "Your last scan didn't turn up any misconfigurations to map against CIS controls."
            : "Run a scan from the sidebar to see your findings grouped by CIS control."
        }
      />
    )
  }

  const groups = new Map<string, { title: string; findings: Finding[] }>()
  for (const f of findings) {
    const { control, title } = getComplianceControl(f)
    if (!groups.has(control)) groups.set(control, { title, findings: [] })
    groups.get(control)!.findings.push(f)
  }

  const sortedGroups = Array.from(groups.entries()).sort((a, b) =>
    a[0].localeCompare(b[0], undefined, { numeric: true }),
  )

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        Mapped to {CIS_BENCHMARK_VERSION} where a clear control applies. This is a best-effort
        mapping — verify against the official benchmark document before citing it formally.
      </p>

      {sortedGroups.map(([control, group]) => (
        <Card key={control}>
          <CardHeader>
            <CardTitle className="flex items-baseline gap-2 text-base">
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-sm">{control}</span>
              {group.title}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {group.findings.map((f) => (
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
      ))}
    </div>
  )
}
