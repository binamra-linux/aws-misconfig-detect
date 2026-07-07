import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { getConfig, updateConfig } from "@/lib/api"

export function Settings() {
  const queryClient = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ["config"], queryFn: getConfig })
  const [days, setDays] = useState("")

  const mutation = useMutation({
    mutationFn: (value: number) => updateConfig(value),
    onSuccess: (result) => {
      queryClient.setQueryData(["config"], result)
      setDays("")
      toast.success("Updated unused-key threshold. Takes effect on the next scan.")
    },
    onError: (error: Error) => toast.error(error.message),
  })

  if (isLoading) {
    return <Skeleton className="h-64 w-full" />
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>AWS Connection</CardTitle>
          <CardDescription>Read-only — edit .env and restart the server to change these.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Region</span>
            <span className="font-mono">{data?.aws_region}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Profile / credentials</span>
            <span className="font-mono">{data?.aws_profile}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>AI Explanations</CardTitle>
          <CardDescription>Read-only — edit .env and restart the server to change this.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Groq model</span>
            <span className="font-mono">{data?.groq_model}</span>
          </div>
        </CardContent>
      </Card>

      <Card className="md:col-span-2">
        <CardHeader>
          <CardTitle>Unused Access Key Threshold</CardTitle>
          <CardDescription>
            Access keys unused for this many days are flagged. Live-editable — takes effect on the
            next scan, but resets to the .env value if the server restarts.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Input
            type="number"
            min={0}
            placeholder={String(data?.iam_unused_key_days ?? 90)}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            className="max-w-32"
          />
          <Button
            onClick={() => {
              const value = Number(days)
              if (!Number.isInteger(value) || value < 0) {
                toast.error("Enter a whole number of days (0 or more).")
                return
              }
              mutation.mutate(value)
            }}
            disabled={mutation.isPending || days === ""}
          >
            Save
          </Button>
          <span className="text-sm text-muted-foreground">Current: {data?.iam_unused_key_days} days</span>
        </CardContent>
      </Card>
    </div>
  )
}
