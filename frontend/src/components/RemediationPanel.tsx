import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, Wrench } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { getRemediationInfo, remediateFinding } from "@/lib/api"

/**
 * Shown inside an expanded finding row. Two-step on purpose: this is the only
 * part of the app that *writes* to AWS, so the exact API call is spelled out and
 * confirmed before anything happens.
 */
export function RemediationPanel({ scanId, findingId }: { scanId: number; findingId: number }) {
  const [confirming, setConfirming] = useState(false)
  const [fixed, setFixed] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ["remediation", scanId, findingId],
    queryFn: () => getRemediationInfo(scanId, findingId),
  })

  const mutation = useMutation({
    mutationFn: () => remediateFinding(scanId, findingId),
    onSuccess: (result) => {
      setFixed(result.message)
      setConfirming(false)
      toast.success(result.message)
      // The finding is stale now -- a re-scan is what proves the fix landed.
      queryClient.invalidateQueries({ queryKey: ["resources"] })
    },
    onError: (e: Error) => {
      setConfirming(false)
      toast.error(e.message)
    },
  })

  if (isLoading || !data?.available) return null

  if (fixed) {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-primary/30 bg-primary/10 p-3 text-sm">
        <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
        <div>
          <p className="font-medium">{fixed}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Run a new scan to confirm the finding is resolved.
          </p>
        </div>
      </div>
    )
  }

  if (!data.enabled) {
    return (
      <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
        <p className="flex items-center gap-2 font-medium text-foreground">
          <Wrench className="size-4" />
          An automatic fix is available for this finding
        </p>
        <p className="mt-1 text-xs">
          Remediation is currently disabled. CloudSentinel is read-only by default — set{" "}
          <code className="rounded bg-muted px-1">REMEDIATION_ENABLED=true</code> and grant the write
          permissions listed in the README to enable one-click fixes.
        </p>
      </div>
    )
  }

  if (confirming) {
    return (
      <div className="space-y-3 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm">
        <div>
          <p className="font-medium">This will modify your AWS account.</p>
          <p className="mt-1 text-muted-foreground">{data.description}</p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="destructive"
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
          >
            {mutation.isPending ? "Applying..." : "Yes, apply this fix"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setConfirming(false)} disabled={mutation.isPending}>
            Cancel
          </Button>
        </div>
      </div>
    )
  }

  return (
    <Button size="sm" variant="outline" onClick={() => setConfirming(true)}>
      <Wrench className="size-4" />
      Fix this
    </Button>
  )
}
