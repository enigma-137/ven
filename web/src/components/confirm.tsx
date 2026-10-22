import { useEffect, useState, type ReactNode } from "react";
import { errorMessage } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Field, Input } from "@/components/ui/form";

interface ConfirmProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  /** When set, the user must type this text to enable the action. */
  typeToConfirm?: string;
  onConfirm: () => Promise<unknown>;
}

export function ConfirmDialog({ open, onOpenChange, title, children, confirmLabel, typeToConfirm, onConfirm }: ConfirmProps) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = !typeToConfirm || typed === typeToConfirm;

  function close(o: boolean) {
    if (!o) {
      setTyped("");
      setError(null);
    }
    onOpenChange(o);
  }

  async function run() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      close(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={close}
      size="sm"
      title={title}
      footer={
        <>
          <Button onClick={() => close(false)}>Cancel</Button>
          <Button variant="danger" disabled={!ready} loading={busy} onClick={run}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-[13.5px]">
        <div>{children}</div>
        {typeToConfirm && (
          <Field label={`Type ${typeToConfirm} to confirm`}>
            {(p) => (
              <Input
                {...p}
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && ready) void run();
                }}
              />
            )}
          </Field>
        )}
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
    </Dialog>
  );
}

interface NameDialogProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  label: string;
  initial?: string;
  submitLabel: string;
  hint?: string;
  onSubmit: (name: string) => Promise<unknown>;
}

/** Small single-field dialog used for creating and renaming environments. */
export function NameDialog({ open, onOpenChange, title, label, initial = "", submitLabel, hint, onSubmit }: NameDialogProps) {
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setName(initial);
      setError(null);
    }
  }, [open, initial]);

  async function submit() {
    if (!name.trim()) {
      setError(`${label} is required.`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit(name.trim());
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="sm"
      title={title}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="name-dialog" loading={busy}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <form
        id="name-dialog"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label={label} error={error} hint={hint}>
          {(p) => <Input {...p} autoFocus maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
      </form>
    </Dialog>
  );
}
