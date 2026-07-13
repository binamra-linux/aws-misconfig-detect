import type { ReactNode } from "react"
import { Boxes, KeyRound, ScanLine, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

const CHECKS: { icon: ReactNode; label: string }[] = [
  { icon: <Boxes className="size-4" />, label: "S3 buckets — public access, encryption, versioning" },
  { icon: <KeyRound className="size-4" />, label: "IAM — permissive policies, missing MFA, stale keys, root account" },
  { icon: <ShieldCheck className="size-4" />, label: "Security groups — sensitive ports exposed to the internet" },
]

export function Welcome({ onScan, scanning }: { onScan: () => void; scanning: boolean }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-6 py-16 text-center">
        <span className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
          <ScanLine className="size-7" />
        </span>
        <div className="space-y-2">
          <h2 className="text-xl font-semibold">Welcome to CloudSentinel</h2>
          <p className="mx-auto max-w-md text-sm text-muted-foreground">
            Run a read-only scan of your AWS account to check for common misconfigurations,
            get an AI-generated risk explanation for each finding, and see how you map to
            the CIS AWS Foundations Benchmark.
          </p>
        </div>
        <div className="grid w-full max-w-md gap-2 text-left">
          {CHECKS.map((c) => (
            <div
              key={c.label}
              className="flex items-center gap-3 rounded-md border border-border bg-muted/30 px-3 py-2 text-sm"
            >
              <span className="text-primary">{c.icon}</span>
              {c.label}
            </div>
          ))}
        </div>
        <Button onClick={onScan} disabled={scanning} size="lg">
          <ScanLine className="size-4" />
          {scanning ? "Scanning..." : "Run First Scan"}
        </Button>
      </CardContent>
    </Card>
  )
}
