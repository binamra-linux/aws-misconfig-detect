import type { ReactNode } from "react"
import {
  BadgeCheck,
  Boxes,
  History as HistoryIcon,
  LayoutDashboard,
  ScanLine,
  Settings as SettingsIcon,
  ShieldAlert,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { ScanProgressEvent } from "@/lib/scanStream"

export type Page = "overview" | "findings" | "resources" | "compliance" | "history" | "settings"

const MAIN_NAV: { page: Page; label: string; icon: ReactNode }[] = [
  { page: "overview", label: "Overview", icon: <LayoutDashboard className="size-4" /> },
  { page: "findings", label: "Findings", icon: <ShieldAlert className="size-4" /> },
  { page: "resources", label: "Resources", icon: <Boxes className="size-4" /> },
  { page: "compliance", label: "Compliance", icon: <BadgeCheck className="size-4" /> },
  { page: "history", label: "History", icon: <HistoryIcon className="size-4" /> },
]

// Must stay in sync with api/main.py's STAGES list (order and keys) -- nothing
// enforces this automatically.
const SCAN_STAGES = ["s3", "iam", "sg", "ebs", "rds", "cloudtrail"]

export function Sidebar({
  page,
  onNavigate,
  onScan,
  scanning,
  scanProgress,
  doneStages,
}: {
  page: Page
  onNavigate: (page: Page) => void
  onScan: () => void
  scanning: boolean
  scanProgress?: ScanProgressEvent | null
  doneStages?: string[]
}) {
  return (
    <aside className="flex w-64 shrink-0 flex-col gap-6 border-r border-border bg-card/40 p-4">
      <div className="flex items-center gap-2 px-2 pt-1">
        <ShieldAlert className="size-6 text-primary" />
        <span className="font-semibold tracking-tight">CloudSentinel</span>
      </div>

      <div className="space-y-2">
        <Button onClick={onScan} disabled={scanning} className="w-full">
          <ScanLine className="size-4" />
          {scanning ? "Scanning..." : "Run Scan"}
        </Button>

        {scanning && (
          <div className="space-y-1.5 px-1">
            <div className="flex gap-1">
              {SCAN_STAGES.map((stage) => (
                <span
                  key={stage}
                  className={cn(
                    "h-1 flex-1 rounded-full bg-muted transition-colors",
                    (doneStages ?? []).includes(stage) && "bg-primary",
                  )}
                />
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{scanProgress?.label ?? "Starting scan..."}</p>
          </div>
        )}
      </div>

      <nav className="flex flex-1 flex-col gap-1">
        {MAIN_NAV.map(({ page: p, label, icon }) => (
          <NavItem key={p} label={label} active={page === p} onClick={() => onNavigate(p)} icon={icon} />
        ))}
      </nav>

      <nav className="border-t border-border pt-2">
        <NavItem
          label="Settings"
          active={page === "settings"}
          onClick={() => onNavigate("settings")}
          icon={<SettingsIcon className="size-4" />}
        />
      </nav>
    </aside>
  )
}

function NavItem({
  label,
  active,
  onClick,
  icon,
}: {
  label: string
  active: boolean
  onClick: () => void
  icon: ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-medium transition-colors",
        active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      {icon}
      {label}
    </button>
  )
}
