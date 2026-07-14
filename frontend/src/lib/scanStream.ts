import type { FindingsResponse } from "@/lib/api"

export interface ScanStage {
  key: string
  label: string
}

export interface ScanProgressEvent {
  stage: string
  label: string
  done: boolean
}

export function startScan({
  onStart,
  onProgress,
  onComplete,
  onError,
  onUnauthorized,
}: {
  /** Fires once with the stage list for this scan. The list is computed server-side
   *  (it depends on how many regions are configured), so the progress bar is built
   *  from real work rather than a hardcoded guess. */
  onStart: (stages: ScanStage[]) => void
  onProgress: (event: ScanProgressEvent) => void
  onComplete: (data: FindingsResponse) => void
  onError: (message: string) => void
  onUnauthorized: () => void
}): () => void {
  const source = new EventSource("/api/scan/stream")

  const close = () => source.close()

  source.addEventListener("start", (e) => {
    onStart(JSON.parse((e as MessageEvent).data).stages)
  })

  source.addEventListener("progress", (e) => {
    onProgress(JSON.parse((e as MessageEvent).data))
  })

  source.addEventListener("complete", (e) => {
    onComplete(JSON.parse((e as MessageEvent).data))
    close()
  })

  // Named "scan_error" (not "error") on the server side, since EventSource
  // reserves the "error" event type for connection failures.
  source.addEventListener("scan_error", (e) => {
    onError(JSON.parse((e as MessageEvent).data).detail as string)
    close()
  })

  // Fires on any raw connection failure -- treat as terminal rather than letting
  // the browser's default auto-reconnect kick in.
  //
  // EventSource can't see the HTTP status, so an expired session (401) is
  // indistinguishable here from a genuine network drop. Probe an authenticated
  // endpoint to tell them apart, otherwise a logged-out user just sees a
  // misleading "lost connection" instead of the login screen.
  source.onerror = () => {
    close()
    fetch("/api/me").then((res) => {
      if (res.status === 401) {
        onUnauthorized()
      } else {
        onError("Lost connection to the scan stream.")
      }
    })
  }

  return close
}
