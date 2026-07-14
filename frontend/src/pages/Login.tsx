import { useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { ShieldAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { login, registerUser } from "@/lib/api"

export function Login({ needsSetup, onAuthed }: { needsSetup: boolean; onAuthed: () => void }) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      needsSetup ? registerUser(username, password) : login(username, password),
    onSuccess: onAuthed,
    onError: (e: Error) => setError(e.message),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    mutation.mutate()
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2">
            <ShieldAlert className="size-6 text-primary" />
            <span className="text-lg font-semibold tracking-tight">CloudSentinel</span>
          </div>
          <CardTitle>{needsSetup ? "Create your admin account" : "Sign in"}</CardTitle>
          <CardDescription>
            {needsSetup
              ? "This is a first run — the account you create here becomes the administrator. Registration closes afterwards."
              : "Enter your credentials to access the dashboard."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <Input
              placeholder="Username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <Input
              type="password"
              placeholder={needsSetup ? "Password (min. 8 characters)" : "Password"}
              autoComplete={needsSetup ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />

            {error && <p className="text-sm text-destructive">{error}</p>}

            <Button type="submit" className="w-full" disabled={mutation.isPending}>
              {mutation.isPending
                ? needsSetup
                  ? "Creating account..."
                  : "Signing in..."
                : needsSetup
                  ? "Create account"
                  : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
