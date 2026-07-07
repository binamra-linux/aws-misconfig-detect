import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Sidebar } from "@/components/Sidebar"
import type { Page } from "@/components/Sidebar"
import { Overview } from "@/pages/Overview"
import { Findings } from "@/pages/Findings"
import { Resources } from "@/pages/Resources"
import { Compliance } from "@/pages/Compliance"
import { History } from "@/pages/History"
import { Settings } from "@/pages/Settings"
import { getFindings, runScan } from "@/lib/api"
import type { FindingsResponse } from "@/lib/api"

const PAGE_TITLES: Record<Page, string> = {
  overview: "Overview",
  findings: "Findings",
  resources: "Resources",
  compliance: "Compliance",
  history: "History",
  settings: "Settings",
}

export default function App() {
  const [page, setPage] = useState<Page>("overview")
  const queryClient = useQueryClient()

  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: getFindings,
  })

  const scanMutation = useMutation({
    mutationFn: runScan,
    onSuccess: (data: FindingsResponse) => {
      queryClient.setQueryData(["findings"], data)
      queryClient.invalidateQueries({ queryKey: ["resources"] })
      queryClient.invalidateQueries({ queryKey: ["history"] })
      toast.success(`Scan complete — ${data.findings.length} finding(s).`)
    },
    onError: (error: Error) => {
      toast.error(error.message)
    },
  })

  return (
    <div className="flex min-h-screen">
      <Sidebar
        page={page}
        onNavigate={setPage}
        onScan={() => scanMutation.mutate()}
        scanning={scanMutation.isPending}
      />
      <main className="flex-1 overflow-y-auto p-8">
        <h1 className="mb-6 text-2xl font-semibold">{PAGE_TITLES[page]}</h1>
        {page === "overview" && (
          <Overview
            data={findingsQuery.data}
            isLoading={findingsQuery.isLoading}
            onGoToFindings={() => setPage("findings")}
          />
        )}
        {page === "findings" && <Findings data={findingsQuery.data} isLoading={findingsQuery.isLoading} />}
        {page === "resources" && <Resources />}
        {page === "compliance" && (
          <Compliance data={findingsQuery.data} isLoading={findingsQuery.isLoading} />
        )}
        {page === "history" && <History />}
        {page === "settings" && <Settings />}
      </main>
    </div>
  )
}
