import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/api"

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
  HIGH: "bg-severity-high/15 text-severity-high border-severity-high/30",
  MEDIUM: "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
  LOW: "bg-severity-low/15 text-severity-low border-severity-low/30",
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
        SEVERITY_STYLES[severity],
      )}
    >
      {severity}
    </span>
  )
}
