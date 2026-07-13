import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode
  title: string
  description: string
  action?: { label: string; onClick: () => void }
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <span className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary">
          {icon}
        </span>
        <div className="space-y-1">
          <p className="font-medium">{title}</p>
          <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
        </div>
        {action && (
          <Button size="sm" onClick={action.onClick} className="mt-2">
            {action.label}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
