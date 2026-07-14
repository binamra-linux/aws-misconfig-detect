import type { ReactNode } from "react"
import {
  BadgeCheck,
  Boxes,
  History as HistoryIcon,
  Home as HomeIcon,
  LayoutDashboard,
  LogOut,
  ScanLine,
  Settings as SettingsIcon,
  ShieldAlert,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { ScanProgressEvent, ScanStage } from "@/lib/scanStream"

export type Page = "home" | "overview" | "findings" | "resources" | "compliance" | "history" | "settings"

const MAIN_NAV: { page: Page; label: string; icon: ReactNode }[] = [
  { page: "home", label: "Home", icon: <HomeIcon className="size-4" /> },
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
  stages,
  scanProgress,
  doneStages,
  user,
  onLogout,
}: {
  page: Page
  onNavigate: (page: Page) => void
  onScan: () => void
  scanning: boolean
  /** Sent by the server at the start of each scan -- the number of segments depends
   *  on how many regions are configured, so it can't be hardcoded here. */
  stages?: ScanStage[]
  scanProgress?: ScanProgressEvent | null
  doneStages?: string[]
  user?: string | null
  onLogout?: () => void
}) {
  const segments = stages ?? []
  const done = doneStages ?? []

  return (
    <aside className="flex w-64 shrink-0 flex-col gap-6 border-r border-border bg-sidebar p-4">
      <button
        onClick={() => onNavigate("home")}
        className="flex items-center gap-2 px-2 pt-1 text-left transition-opacity hover:opacity-80"
      >
        <ShieldAlert className="size-6 text-primary" />
        <span className="font-semibold tracking-tight">CloudSentinel</span>
      </button>

      <div className="space-y-2">
        <Button onClick={onScan} disabled={scanning} className="w-full">
          <ScanLine className="size-4" />
          {scanning ? "Scanning..." : "Run Scan"}
        </Button>

        {scanning && (
          <div className="space-y-1.5 px-1">
            <div className="flex gap-0.5">
              {segments.length > 0 ? (
                segments.map((s) => (
                  <span
                    key={s.key}
                    className={cn(
                      "h-1 flex-1 rounded-full bg-muted transition-colors",
                      done.includes(s.key) && "bg-primary",
                    )}
                  />
                ))
              ) : (
                <span className="h-1 flex-1 animate-pulse rounded-full bg-muted" />
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {scanProgress?.label ?? "Starting scan..."}
              {segments.length > 0 && ` (${done.length}/${segments.length})`}
            </p>
          </div>
        )}
      </div>

      <nav className="flex flex-1 flex-col gap-1">
        {MAIN_NAV.map(({ page: p, label, icon }) => (
          <NavItem key={p} label={label} active={page === p} onClick={() => onNavigate(p)} icon={icon} />
        ))}
      </nav>

      <nav className="space-y-1 border-t border-border pt-2">
        <NavItem
          label="Settings"
          active={page === "settings"}
          onClick={() => onNavigate("settings")}
          icon={<SettingsIcon className="size-4" />}
        />
        {user && onLogout && (
          <>
            <NavItem label="Sign out" active={false} onClick={onLogout} icon={<LogOut className="size-4" />} />
            <p className="px-3 pt-1 text-xs text-muted-foreground">Signed in as {user}</p>
          </>
        )}
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
        "flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-medium transition-colors",
        active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      {icon}
      {label}
    </button>
  )
}
