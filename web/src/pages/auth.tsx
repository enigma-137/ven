import { useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError, errorMessage, type SessionState } from "@/lib/api";
import { copyText } from "@/lib/utils";
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

  // Held in memory only until the user confirms they saved the key.
  const [created, setCreated] = useState<{ session: SessionState; recoveryKey: string } | null>(null);

  const tooShort = [...password].length < MIN_PASSWORD;
  const mismatch = confirm !== password;

  if (created) {
    return (
      <RecoveryKeyScreen
        recoveryKey={created.recoveryKey}
        onDone={() => {
          const s = created.session;
          setCreated(null);
          apply(s);
        }}
      />
    );
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (tooShort || mismatch || !ack) return;
    setBusy(true);
    setError(null);
    try {
      const { recoveryKey, ...s } = await api.initVault(password);
      setPassword("");
      setConfirm("");
      setCreated({ session: s, recoveryKey });
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
        <Alert tone="warning" title="Keep it safe">
          Nobody can reset this password for you. Next, VEN shows a one-time recovery key that can.
        </Alert>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-accent" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>I understand that without the password and the recovery key, my values cannot be decrypted.</span>
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

function RecoveryKeyScreen({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <Shell title="Save your recovery key" subtitle="This is the only time it is shown.">
      <div className="flex flex-col gap-4">
        <code className="block select-all break-all rounded-panel border border-border bg-surface px-3 py-3 text-center font-mono text-[15px] tracking-wide text-fg">
          {recoveryKey}
        </code>
        <Button
          variant="secondary"
          className="justify-center"
          onClick={async () => {
            try {
              await copyText(recoveryKey);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? "Copied" : "Copy recovery key"}
        </Button>
        <p className="text-[13px] text-muted">
          Store it in a password manager or write it down, away from this computer. If you forget your master password, run{" "}
          <code className="rounded bg-surface px-1 py-0.5">ven password reset</code> and enter this key. Anyone with it can set a new password, so keep it private.
        </p>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-accent" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <span>I saved my recovery key somewhere safe.</span>
        </label>
        <Button variant="primary" className="justify-center" disabled={!saved} onClick={onDone}>
          Continue
        </Button>
      </div>
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
