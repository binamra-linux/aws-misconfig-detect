import { Fragment, useMemo, useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { ChevronRight, Download, ShieldCheck } from "lucide-react"
import ReactMarkdown from "react-markdown"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { SeverityBadge } from "@/components/SeverityBadge"
import { EmptyState } from "@/components/EmptyState"
import { RemediationPanel } from "@/components/RemediationPanel"
import { cn } from "@/lib/utils"
import { explainFinding } from "@/lib/api"
import { generateReportPdf } from "@/lib/report"
import type { FindingsResponse, Severity } from "@/lib/api"

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

export function Findings({ data, isLoading }: { data?: FindingsResponse; isLoading: boolean }) {
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("all")
  const [resourceTypeFilter, setResourceTypeFilter] = useState("all")
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [explanations, setExplanations] = useState<Record<number, string>>({})

  const findings = data?.findings ?? []

  const resourceTypes = useMemo(
    () => Array.from(new Set(findings.map((f) => f.resource_type))).sort(),
    [findings],
  )

  const filtered = findings.filter((f) => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false
    if (resourceTypeFilter !== "all" && f.resource_type !== resourceTypeFilter) return false
    if (search && !`${f.description} ${f.resource_id}`.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const explainMutation = useMutation({
    mutationFn: ({ scanId, findingId }: { scanId: number; findingId: number }) =>
      explainFinding(scanId, findingId),
    onSuccess: (result, variables) => {
      setExplanations((prev) => ({ ...prev, [variables.findingId]: result.explanation }))
    },
    onError: (error: Error) => {
      toast.error(error.message)
    },
  })

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  if (findings.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck className="size-6" />}
        title={data?.scanned_at ? "No issues found" : "No findings yet"}
        description={
          data?.scanned_at
            ? "Your last scan didn't turn up any misconfigurations."
            : "Run a scan from the sidebar to check your AWS account."
        }
      />
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-3">
          <Input
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-xs"
          />
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              {SEVERITY_ORDER.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={resourceTypeFilter} onValueChange={setResourceTypeFilter}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Resource type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All resource types</SelectItem>
              {resourceTypes.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => data && generateReportPdf(data, explanations)}
        >
          <Download className="size-4" />
          Download Report
        </Button>
      </div>

      <div className="overflow-hidden rounded-lg border border-border">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-8" />
              <TableHead>Severity</TableHead>
              <TableHead>Finding</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Region</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((f) => {
              const isExpanded = expandedId === f.id
              return (
                <Fragment key={f.id}>
                  <TableRow
                    key={f.id}
                    className="cursor-pointer"
                    data-state={isExpanded ? "selected" : undefined}
                    onClick={() => setExpandedId(isExpanded ? null : f.id)}
                  >
                    <TableCell>
                      <ChevronRight
                        className={cn("size-4 text-muted-foreground transition-transform", isExpanded && "rotate-90")}
                      />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell className="max-w-md">
                      <p className="font-medium">{f.check_type}</p>
                      <p className="truncate text-xs text-muted-foreground">{f.description}</p>
                    </TableCell>
                    <TableCell className="text-sm">
                      <p>{f.resource_type}</p>
                      <p className="text-xs text-muted-foreground">{f.resource_id}</p>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{f.region ?? "—"}</TableCell>
                  </TableRow>

                  {isExpanded && (
                    <TableRow key={`${f.id}-detail`} className="hover:bg-transparent">
                      <TableCell colSpan={5} className="whitespace-normal bg-muted/30 p-0">
                        <div className="animate-in fade-in slide-in-from-top-1 space-y-4 p-5 duration-150">
                          <div>
                            <h4 className="mb-1 text-sm font-semibold">Raw detail</h4>
                            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
                              {JSON.stringify(f.detail, null, 2)}
                            </pre>
                          </div>

                          <div>
                            <h4 className="mb-2 text-sm font-semibold">AI Explanation &amp; Fix</h4>
                            {explanations[f.id] ? (
                              <div className="prose prose-invert max-w-none prose-headings:text-sm prose-headings:font-semibold prose-p:text-[17px] prose-p:leading-[1.47] prose-p:tracking-[-0.02em] prose-li:text-[17px] prose-li:leading-[1.47] prose-pre:bg-background">
                                <ReactMarkdown>{explanations[f.id]}</ReactMarkdown>
                              </div>
                            ) : (
                              <Button
                                size="sm"
                                onClick={() =>
                                  data && explainMutation.mutate({ scanId: data.scan_id, findingId: f.id })
                                }
                                disabled={explainMutation.isPending}
                              >
                                {explainMutation.isPending ? "Asking Groq..." : "Get AI Explanation & Fix"}
                              </Button>
                            )}
                          </div>

                          {data && <RemediationPanel scanId={data.scan_id} findingId={f.id} />}
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
      </div>
      {filtered.length === 0 && <p className="text-sm text-muted-foreground">No findings match your filters.</p>}
    </div>
  )
}
