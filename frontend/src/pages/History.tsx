import { useQuery } from "@tanstack/react-query"
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { getHistory } from "@/lib/api"

const TOOLTIP_STYLE = {
  background: "var(--card)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  fontSize: 12,
}

const AXIS_TICK = { fontSize: 11, fill: "var(--muted-foreground)" }

export function History() {
  const { data, isLoading } = useQuery({ queryKey: ["history"], queryFn: getHistory })
  const scans = data?.scans ?? []

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />
  }

  if (scans.length === 0) {
    return (
      <p className="text-muted-foreground">
        No scan history yet. Run a scan from the sidebar to start tracking trends.
      </p>
    )
  }

  const chartData = scans.map((s) => ({
    time: new Date(s.scanned_at).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }),
    score: s.score,
    findings: s.total_findings,
  }))

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Security Score Over Time</CardTitle>
        </CardHeader>
        <CardContent className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="time" tick={AXIS_TICK} />
              <YAxis domain={[0, 100]} tick={AXIS_TICK} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="score" stroke="var(--primary)" strokeWidth={2} dot={{ r: 3 }} name="Score (%)" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Findings Over Time</CardTitle>
        </CardHeader>
        <CardContent className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="time" tick={AXIS_TICK} />
              <YAxis allowDecimals={false} tick={AXIS_TICK} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line
                type="monotone"
                dataKey="findings"
                stroke="var(--severity-critical)"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Total Findings"
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan Log</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Scanned At</TableHead>
                <TableHead>Score</TableHead>
                <TableHead>Total Findings</TableHead>
                <TableHead>Critical</TableHead>
                <TableHead>High</TableHead>
                <TableHead>Medium</TableHead>
                <TableHead>Low</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {[...scans].reverse().map((s) => (
                <TableRow key={s.scanned_at}>
                  <TableCell className="text-sm">{new Date(s.scanned_at).toLocaleString()}</TableCell>
                  <TableCell className="text-sm">
                    {s.score}% ({s.label})
                  </TableCell>
                  <TableCell className="text-sm">{s.total_findings}</TableCell>
                  <TableCell className="text-sm">{s.severity_counts.CRITICAL}</TableCell>
                  <TableCell className="text-sm">{s.severity_counts.HIGH}</TableCell>
                  <TableCell className="text-sm">{s.severity_counts.MEDIUM}</TableCell>
                  <TableCell className="text-sm">{s.severity_counts.LOW}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
