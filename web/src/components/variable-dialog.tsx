import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff } from "lucide-react";
import { api, errorMessage, type Variable, type VariableType } from "@/lib/api";
import { cn, KEY_PATTERN, suggestType } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Field, Input, Textarea } from "@/components/ui/form";
import { useToast } from "@/components/ui/toast";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  project: string;
  env: string;
  /** Present when editing. */
  variable?: Variable;
}

const MAX_VALUE = 64 * 1024;

export function VariableDialog({ open, onOpenChange, project, env, variable }: Props) {
  const qc = useQueryClient();
  const toast = useToast();
  const editing = !!variable;
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [original, setOriginal] = useState<string | null>(null);
  const [type, setType] = useState<VariableType>("secret");
  const [typeTouched, setTypeTouched] = useState(false);
  const [description, setDescription] = useState("");
  const [show, setShow] = useState(false);
  const [loadingValue, setLoadingValue] = useState(false);
  const [touched, setTouched] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset local state on open; for edits, fetch the value explicitly.
  useEffect(() => {
    if (!open) {
      setValue("");
      setOriginal(null);
      return;
    }
    setKey(variable?.key ?? "");
    setType(variable?.type ?? "secret");
    setTypeTouched(editing);
    setDescription(variable?.description ?? "");
    setShow(variable?.type === "text");
    setTouched(false);
    setError(null);
    setValue("");
    setOriginal(null);
    if (variable) {
      let cancelled = false;
      setLoadingValue(true);
      api
        .reveal(variable.id)
        .then((r) => {
          if (cancelled) return;
          setValue(r.value);
          setOriginal(r.value);
        })
        .catch((e) => !cancelled && setError(errorMessage(e)))
        .finally(() => !cancelled && setLoadingValue(false));
      return () => {
        cancelled = true;
      };
    }
  }, [open, variable, editing]);

  const keyError = !key ? "Key is required." : !KEY_PATTERN.test(key) ? "Start with a letter or underscore; use letters, digits, underscores and dots." : key.length > 256 ? "Keys are at most 256 characters." : null;
  const valueError = new Blob([value]).size > MAX_VALUE ? "Values are at most 64 KiB." : value.includes("\0") ? "Values cannot contain NUL characters." : null;
  const multiline = value.includes("\n");

  function onKeyChange(k: string) {
    setKey(k);
    if (!typeTouched) setType(suggestType(k));
  }

  async function save() {
    setTouched(true);
    if (keyError || valueError || loadingValue) return;
    setSaving(true);
    setError(null);
    try {
      if (variable) {
        const patch: { key?: string; value?: string; type?: VariableType; description?: string } = {};
        if (key !== variable.key) patch.key = key;
        if (original === null || value !== original) patch.value = value;
        if (type !== variable.type) patch.type = type;
        if (description !== variable.description) patch.description = description;
        await api.updateVariable(variable.id, patch);
        toast.success(`Saved ${key}`);
      } else {
        await api.createVariable(project, env, { key, value, type, description });
        toast.success(`Added ${key}`);
      }
      qc.invalidateQueries({ queryKey: ["variables", project, env] });
      qc.invalidateQueries({ queryKey: ["text-values", project, env] });
      qc.invalidateQueries({ queryKey: ["project", project] });
      setValue("");
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={editing ? `Edit ${variable?.key}` : "Add variable"}
      description={`${project} / ${env}`}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="variable-form" loading={saving} disabled={loadingValue}>
            {editing ? "Save changes" : "Add variable"}
          </Button>
        </>
      }
    >
      <form
        id="variable-form"
        className="flex flex-col gap-4"
        noValidate
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Field label="Key" error={touched ? keyError : null} hint="Letters, digits, underscores and dots, for example DATABASE_URL.">
          {(p) => (
            <Input
              {...p}
              autoFocus={!editing}
              spellCheck={false}
              className="font-mono"
              value={key}
              maxLength={256}
              onChange={(e) => onKeyChange(e.target.value)}
            />
          )}
        </Field>

        <Field
          label="Value"
          error={touched ? valueError : null}
          hint={loadingValue ? "Decrypting current value…" : multiline && !show ? "Multi-line values are shown while editing." : "Stored encrypted regardless of type."}
        >
          {(p) => (
            <div className="flex items-start gap-2">
              {show || multiline ? (
                <Textarea
                  {...p}
                  spellCheck={false}
                  className="font-mono"
                  rows={Math.min(8, Math.max(2, value.split("\n").length))}
                  value={value}
                  disabled={loadingValue}
                  onChange={(e) => setValue(e.target.value)}
                />
              ) : (
                <Input
                  {...p}
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  className="font-mono"
                  value={value}
                  disabled={loadingValue}
                  onChange={(e) => setValue(e.target.value)}
                />
              )}
              {!multiline && (
                <Button size="icon" aria-label={show ? "Hide value" : "Show value"} aria-pressed={show} onClick={() => setShow(!show)}>
                  {show ? <EyeOff size={15} aria-hidden /> : <Eye size={15} aria-hidden />}
                </Button>
              )}
            </div>
          )}
        </Field>

        <fieldset>
          <legend className="mb-1.5 text-[13px] font-medium">Display type</legend>
          <div role="radiogroup" className="inline-flex rounded-control border border-border p-0.5">
            {(["secret", "text"] as const).map((t) => (
              <label
                key={t}
                className={cn(
                  "cursor-pointer rounded-[4px] px-3 py-1 text-[13px] font-medium has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent",
                  type === t ? "bg-accent text-white" : "text-muted hover:text-fg",
                )}
              >
                <input
                  type="radio"
                  name="vtype"
                  value={t}
                  className="sr-only"
                  checked={type === t}
                  onChange={() => {
                    setType(t);
                    setTypeTouched(true);
                  }}
                />
                {t === "secret" ? "Secret" : "Text"}
              </label>
            ))}
          </div>
          <p className="mt-1.5 text-[13px] text-muted">
            {type === "secret" ? "Masked until you reveal it." : "Shown in the table while unlocked."}
            {!editing && !typeTouched && key && " Suggested from the key name."}
          </p>
        </fieldset>

        <Field label="Description" optional>
          {(p) => <Input {...p} maxLength={500} value={description} onChange={(e) => setDescription(e.target.value)} />}
        </Field>
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Dialog>
  );
}
