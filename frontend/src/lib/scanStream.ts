import type { FindingsResponse } from "@/lib/api"

export interface ScanProgressEvent {
  stage: string
  label: string
  done: boolean
}

export function startScan({
  onProgress,
  onComplete,
  onError,
}: {
  onProgress: (event: ScanProgressEvent) => void
  onComplete: (data: FindingsResponse) => void
  onError: (message: string) => void
}): () => void {
  const source = new EventSource("/api/scan/stream")

  const close = () => source.close()

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
    const detail = JSON.parse((e as MessageEvent).data).detail as string
    onError(detail)
    close()
  })

  // Fires on any raw connection failure (initial 409, network drop, etc.) --
  // treat as terminal rather than letting the browser's default EventSource
  // auto-reconnect kick in, which would otherwise surface a confusing "scan
  // already in progress" toast on an unrelated reconnect blip.
  source.onerror = () => {
    onError("Lost connection to the scan stream.")
    close()
  }

  return close
}
