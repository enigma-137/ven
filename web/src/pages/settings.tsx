import { useEffect, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Lock } from "lucide-react";
import { api, ApiError, errorMessage } from "@/lib/api";
import { useSession } from "@/lib/session";
import { PageHeader } from "@/components/layout";
import { Button } from "@/components/ui/button";
import { Alert, Field, Input } from "@/components/ui/form";
import { useToast } from "@/components/ui/toast";

function Section({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid gap-4 border-b border-border py-6 first:pt-0 last:border-0 md:grid-cols-[260px_1fr] md:gap-8">
      <div>
        <h2 className="text-[14.5px] font-semibold">{title}</h2>
        {description && <p className="mt-1 text-[13px] text-muted">{description}</p>}
      </div>
      <div className="max-w-md">{children}</div>
    </section>
  );
}

const MIN_PASSWORD = 10;

export function SettingsPage() {
  const { lock, setAutoLockMinutes } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings });
  const [minutes, setMinutes] = useState("");
  const [savingLock, setSavingLock] = useState(false);
  const [lockError, setLockError] = useState<string | null>(null);

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwTouched, setPwTouched] = useState(false);
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data) setMinutes(String(settings.data.autoLockMinutes));
  }, [settings.data]);

  async function saveAutoLock() {
    const n = Number(minutes);
    if (!Number.isInteger(n) || n < 1 || n > 240) {
      setLockError("Enter a whole number of minutes between 1 and 240.");
      return;
    }
    setSavingLock(true);
    setLockError(null);
    try {
      const s = await api.updateSettings(n);
      qc.setQueryData(["settings"], s);
      setAutoLockMinutes(s.autoLockMinutes);
      toast.success(`Auto-lock set to ${s.autoLockMinutes} minutes`);
    } catch (e) {
      setLockError(errorMessage(e));
    } finally {
      setSavingLock(false);
    }
  }

  const nextTooShort = [...next].length < MIN_PASSWORD;
  const mismatch = next !== confirm;

  async function changePassword() {
    setPwTouched(true);
    if (!current || nextTooShort || mismatch) return;
    setPwBusy(true);
    setPwError(null);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setPwTouched(false);
      toast.success("Master password changed");
    } catch (e) {
      setPwError(e instanceof ApiError && e.code === "incorrect_password" ? "The current master password is incorrect." : errorMessage(e));
    } finally {
      setPwBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Settings" description="Local vault configuration. These settings apply to this machine only." />
      {settings.isError && <Alert tone="danger">{errorMessage(settings.error)}</Alert>}
      <div className="rounded-panel border border-border px-5 py-6 md:px-6">
        <Section title="Vault location" description="Encrypted SQLite database. Back it up together with your master password.">
          <code className="block rounded-control border border-border bg-surface px-3 py-2 break-all">{settings.data?.vaultPath ?? "…"}</code>
          {settings.data && (
            <p className="mt-2 text-[13px] text-muted">
              Key derivation: {settings.data.kdf.algorithm} · {Math.round(settings.data.kdf.memoryKiB / 1024)} MiB · {settings.data.kdf.iterations} iterations ·{" "}
              parallelism {settings.data.kdf.parallelism}. Values: AES-256-GCM.
            </p>
          )}
        </Section>

        <Section title="Auto-lock" description="Lock the dashboard after this many minutes without activity. The CLI always asks for the password.">
          <form
            className="flex items-end gap-2"
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              void saveAutoLock();
            }}
          >
            <div className="w-32">
              <Field label="Minutes" error={null}>
                {(p) => <Input {...p} type="number" min={1} max={240} inputMode="numeric" value={minutes} onChange={(e) => setMinutes(e.target.value)} />}
              </Field>
            </div>
            <Button type="submit" loading={savingLock}>
              Save
            </Button>
          </form>
          {lockError && <p className="mt-2 text-[13px] text-danger">{lockError}</p>}
        </Section>

        <Section title="Master password" description="Re-wraps the vault key. Stored values are not re-encrypted. There is no password recovery in V1.">
          <form
            className="flex flex-col gap-3"
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              void changePassword();
            }}
          >
            <Field label="Current password" error={pwTouched && !current ? "Enter your current password." : null}>
              {(p) => <Input {...p} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />}
            </Field>
            <Field label="New password" hint={`At least ${MIN_PASSWORD} characters.`} error={pwTouched && nextTooShort ? `Use at least ${MIN_PASSWORD} characters.` : null}>
              {(p) => <Input {...p} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />}
            </Field>
            <Field label="Confirm new password" error={pwTouched && mismatch ? "Passwords do not match." : null}>
              {(p) => <Input {...p} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
            </Field>
            {pwError && <Alert tone="danger">{pwError}</Alert>}
            <div>
              <Button type="submit" variant="primary" loading={pwBusy}>
                Change password
              </Button>
            </div>
          </form>
        </Section>

        <Section title="Application">
          <dl className="grid grid-cols-[120px_1fr] gap-y-1.5 text-[13.5px]">
            <dt className="text-muted">Version</dt>
            <dd className="font-mono">{settings.data?.version ?? "…"}</dd>
            <dt className="text-muted">Schema</dt>
            <dd className="font-mono">v{settings.data?.schemaVersion ?? "…"}</dd>
          </dl>
        </Section>

        <Section title="Lock vault" description="Clears the vault key from the server and all loaded data from this page.">
          <Button onClick={() => void lock()}>
            <Lock size={14} aria-hidden />
            Lock now
          </Button>
        </Section>
      </div>
    </>
  );
}
