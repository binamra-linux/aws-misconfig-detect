import { useMemo, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { SeverityBadge } from "@/components/SeverityBadge"
import { getResources } from "@/lib/api"

export function Resources() {
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState("all")
  const [resourceTypeFilter, setResourceTypeFilter] = useState("all")

  const { data, isLoading } = useQuery({ queryKey: ["resources"], queryFn: getResources })
  const checks = data?.checks ?? []

  const resourceTypes = useMemo(
    () => Array.from(new Set(checks.map((c) => c.resource_type))).sort(),
    [checks],
  )

  const filtered = checks.filter((c) => {
    if (statusFilter !== "all" && c.status !== statusFilter) return false
    if (resourceTypeFilter !== "all" && c.resource_type !== resourceTypeFilter) return false
    if (search && !`${c.description} ${c.resource_id}`.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  if (checks.length === 0) {
    return <p className="text-muted-foreground">No resources scanned yet. Run a scan from the sidebar.</p>
  }

  const passCount = checks.filter((c) => c.status === "PASS").length

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {passCount} of {checks.length} checks passed across all scanned resources.
      </p>

      <div className="flex flex-wrap gap-3">
        <Input
          placeholder="Search resources..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="PASS">Pass</SelectItem>
            <SelectItem value="FAIL">Fail</SelectItem>
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

      <div className="overflow-hidden rounded-lg border border-border">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Status</TableHead>
              <TableHead>Check</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Region</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((c) => (
              <TableRow key={c.id}>
                <TableCell>
                  {c.status === "PASS" ? (
                    <Badge variant="outline" className="border-primary/30 bg-primary/15 text-primary">
                      PASS
                    </Badge>
                  ) : (
                    <SeverityBadge severity={c.severity ?? "LOW"} />
                  )}
                </TableCell>
                <TableCell className="max-w-md">
                  <p className="font-medium">{c.check_type}</p>
                  <p className="truncate text-xs text-muted-foreground">{c.description}</p>
                </TableCell>
                <TableCell className="text-sm">
                  <p>{c.resource_type}</p>
                  <p className="text-xs text-muted-foreground">{c.resource_id}</p>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">{c.region ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {filtered.length === 0 && <p className="text-sm text-muted-foreground">No resources match your filters.</p>}
    </div>
  )
}
