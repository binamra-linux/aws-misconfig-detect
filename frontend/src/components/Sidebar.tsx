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

export type Page = "overview" | "findings" | "resources" | "compliance" | "history" | "settings"

const MAIN_NAV: { page: Page; label: string; icon: ReactNode }[] = [
  { page: "overview", label: "Overview", icon: <LayoutDashboard className="size-4" /> },
  { page: "findings", label: "Findings", icon: <ShieldAlert className="size-4" /> },
  { page: "resources", label: "Resources", icon: <Boxes className="size-4" /> },
  { page: "compliance", label: "Compliance", icon: <BadgeCheck className="size-4" /> },
  { page: "history", label: "History", icon: <HistoryIcon className="size-4" /> },
]

export function Sidebar({
  page,
  onNavigate,
  onScan,
  scanning,
}: {
  page: Page
  onNavigate: (page: Page) => void
  onScan: () => void
  scanning: boolean
}) {
  return (
    <aside className="flex w-64 shrink-0 flex-col gap-6 border-r border-border bg-card/40 p-4">
      <div className="flex items-center gap-2 px-2 pt-1">
        <ShieldAlert className="size-6 text-primary" />
        <span className="font-semibold tracking-tight">AWS Misconfig Detector</span>
      </div>

      <Button onClick={onScan} disabled={scanning} className="w-full">
        <ScanLine className="size-4" />
        {scanning ? "Scanning..." : "Run Scan"}
      </Button>

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
