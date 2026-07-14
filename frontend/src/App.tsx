import { useCallback, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Sidebar } from "@/components/Sidebar"
import type { Page } from "@/components/Sidebar"
import { Home } from "@/pages/Home"
import { Overview } from "@/pages/Overview"
import { Findings } from "@/pages/Findings"
import { Resources } from "@/pages/Resources"
import { Compliance } from "@/pages/Compliance"
import { History } from "@/pages/History"
import { Settings } from "@/pages/Settings"
import { Login } from "@/pages/Login"
import { getAuthStatus, getFindings, logout, resetApp } from "@/lib/api"
import { startScan } from "@/lib/scanStream"
import type { ScanProgressEvent, ScanStage } from "@/lib/scanStream"

const PAGE_TITLES: Record<Page, string> = {
  home: "Home",
  overview: "Overview",
  findings: "Findings",
  resources: "Resources",
  compliance: "Compliance",
  history: "History",
  settings: "Settings",
}

export default function App() {
  const [page, setPage] = useState<Page>("home")
  const [scanning, setScanning] = useState(false)
  const [stages, setStages] = useState<ScanStage[]>([])
  const [scanProgress, setScanProgress] = useState<ScanProgressEvent | null>(null)
  const [doneStages, setDoneStages] = useState<string[]>([])
  const queryClient = useQueryClient()

  const authQuery = useQuery({ queryKey: ["auth"], queryFn: getAuthStatus, retry: false })

  const authed = Boolean(authQuery.data?.user)

  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: getFindings,
    enabled: authed,
    retry: false,
  })

  const showLogin = useCallback(() => {
    queryClient.setQueryData(["auth"], { needs_setup: false, user: null })
    queryClient.removeQueries({ queryKey: ["findings"] })
  }, [queryClient])

  const runScan = useCallback(() => {
    if (scanning) return
    setScanning(true)
    setStages([])
    setDoneStages([])
    setScanProgress(null)

    startScan({
      onStart: setStages,
      onProgress: (event) => {
        setScanProgress(event)
        setDoneStages((prev) => [...prev, event.stage])
      },
      onComplete: (data) => {
        setScanning(false)
        setScanProgress(null)
        queryClient.setQueryData(["findings"], data)
        queryClient.invalidateQueries({ queryKey: ["resources"] })
        queryClient.invalidateQueries({ queryKey: ["history"] })
        toast.success(`Scan complete — ${data.findings.length} finding(s).`)
      },
      onError: (message) => {
        setScanning(false)
        setScanProgress(null)
        toast.error(message)
      },
      onUnauthorized: () => {
        setScanning(false)
        setScanProgress(null)
        toast.error("Your session expired. Please sign in again.")
        showLogin()
      },
    })
  }, [scanning, queryClient, showLogin])

  const resetMutation = useMutation({
    mutationFn: resetApp,
    onSuccess: (data) => {
      queryClient.setQueryData(["findings"], data)
      queryClient.invalidateQueries({ queryKey: ["resources"] })
      queryClient.invalidateQueries({ queryKey: ["history"] })
      setPage("home")
      toast.success("Reset complete — all scan data and history cleared.")
    },
    onError: (error: Error) => toast.error(error.message),
  })

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      showLogin()
      setPage("home")
    },
    onError: (error: Error) => toast.error(error.message),
  })

  if (authQuery.isLoading) {
    return <div className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</div>
  }

  if (!authed) {
    return (
      <Login
        needsSetup={Boolean(authQuery.data?.needs_setup)}
        onAuthed={() => queryClient.invalidateQueries({ queryKey: ["auth"] })}
      />
    )
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar
        page={page}
        onNavigate={setPage}
        onScan={runScan}
        scanning={scanning}
        stages={stages}
        scanProgress={scanProgress}
        doneStages={doneStages}
        user={authQuery.data?.user ?? null}
        onLogout={() => logoutMutation.mutate()}
      />
      <main className="flex-1 overflow-y-auto p-8">
        <h1 className="mb-6 text-[28px] font-semibold tracking-[-0.02em]">{PAGE_TITLES[page]}</h1>
        {page === "home" && (
          <Home
            data={findingsQuery.data}
            isLoading={findingsQuery.isLoading}
            onScan={runScan}
            scanning={scanning}
            onNavigate={setPage}
          />
        )}
        {page === "overview" && (
          <Overview
            data={findingsQuery.data}
            isLoading={findingsQuery.isLoading}
            onGoToFindings={() => setPage("findings")}
            onScan={runScan}
            scanning={scanning}
          />
        )}
        {page === "findings" && <Findings data={findingsQuery.data} isLoading={findingsQuery.isLoading} />}
        {page === "resources" && <Resources />}
        {page === "compliance" && (
          <Compliance data={findingsQuery.data} isLoading={findingsQuery.isLoading} />
        )}
        {page === "history" && <History />}
        {page === "settings" && (
          <Settings onReset={() => resetMutation.mutate()} resetting={resetMutation.isPending} />
        )}
      </main>
    </div>
  )
}
