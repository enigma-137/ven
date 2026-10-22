import { useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { useSession } from "@/lib/session";
import { Button } from "@/components/ui/button";
import { Alert, Field, Input } from "@/components/ui/form";

const MIN_PASSWORD = 10;

function Shell({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  return (
    <main className="flex min-h-full items-center justify-center bg-surface px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-6 flex items-baseline gap-2">
          <span className="text-[22px] font-bold tracking-tight text-fg">VEN</span>
          <span className="text-[13px] text-muted">Local environment-variable vault</span>
        </div>
        <section className="rounded-panel border border-border bg-white p-6">
          <h1 className="text-[17px] font-semibold">{title}</h1>
          {subtitle && <p className="mt-1 text-[13px] text-muted">{subtitle}</p>}
          <div className="mt-5">{children}</div>
        </section>
      </div>
    </main>
  );
}

export function LoadingScreen() {
  return (
    <main className="flex min-h-full items-center justify-center" aria-busy="true">
      <p className="text-muted">Loading VEN…</p>
    </main>
  );
}

export function NoSessionScreen({ error }: { error?: string | null }) {
  return (
    <Shell title="Open the dashboard from your terminal" subtitle="The dashboard only starts a session from the link printed by ven ui.">
      <div className="flex flex-col gap-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <ol className="list-decimal space-y-2 pl-5 text-[13px] text-fg">
          <li>
            Run <code className="rounded bg-surface px-1 py-0.5">ven ui</code> in a terminal.
          </li>
          <li>Open the link it prints (it contains a one-time launch token).</li>
        </ol>
        <p className="text-[13px] text-muted">
          Sessions end when the server stops or after inactivity. Reopen the printed link to start a new one.
        </p>
      </div>
    </Shell>
  );
}

function retryMessage(err: unknown): string {
  if (err instanceof ApiError && err.code === "incorrect_password") return "Incorrect master password.";
  return errorMessage(err);
}

export function SetupScreen() {
  const { apply } = useSession();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [ack, setAck] = useState(false);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tooShort = [...password].length < MIN_PASSWORD;
  const mismatch = confirm !== password;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (tooShort || mismatch || !ack) return;
    setBusy(true);
    setError(null);
    try {
      const s = await api.initVault(password);
      setPassword("");
      setConfirm("");
      apply(s);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell title="Create your vault" subtitle="Choose a master password. It encrypts every value stored in VEN.">
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <Field label="Master password" hint={`At least ${MIN_PASSWORD} characters.`} error={touched && tooShort ? `Use at least ${MIN_PASSWORD} characters.` : null}>
          {(p) => <Input {...p} type="password" autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />}
        </Field>
        <Field label="Confirm master password" error={touched && mismatch ? "Passwords do not match." : null}>
          {(p) => <Input {...p} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
        </Field>
        <Alert tone="warning" title="No recovery">
          VEN V1 has no password recovery. If you forget this password, your stored values cannot be decrypted.
        </Alert>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-accent" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>I understand that the master password cannot be recovered.</span>
        </label>
        {touched && !ack && <p className="-mt-2 text-[13px] text-danger">Please confirm you understand.</p>}
        {error && <Alert tone="danger">{error}</Alert>}
        <Button type="submit" variant="primary" loading={busy} className="justify-center">
          Create vault
        </Button>
      </form>
    </Shell>
  );
}

export function UnlockScreen() {
  const { apply } = useSession();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) {
      setError("Enter your master password.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const s = await api.unlock(password);
      setPassword("");
      apply(s);
    } catch (err) {
      setPassword("");
      setError(retryMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell title="Unlock vault" subtitle="Enter your master password to view and edit variables.">
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <Field label="Master password" error={error}>
          {(p) => (
            <Input {...p} type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
          )}
        </Field>
        <Button type="submit" variant="primary" loading={busy} className="justify-center">
          Unlock
        </Button>
        <p className="text-[13px] text-muted">The vault locks automatically after a period of inactivity.</p>
      </form>
    </Shell>
  );
}
