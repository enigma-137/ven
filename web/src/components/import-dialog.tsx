import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Tabs from "@radix-ui/react-tabs";
import { FileUp } from "lucide-react";
import { api, errorMessage, type ImportPreview, type VariableType } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Field, Input, Textarea } from "@/components/ui/form";
import { useToast } from "@/components/ui/toast";

const MAX_BYTES = 1024 * 1024;
const NEW = "__new__";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  project: string;
  env: string;
  onImported: (project: string, env: string) => void;
}

type Step = "source" | "preview" | "confirm";
type Resolution = "keep" | "overwrite";

const selectCls =
  "h-9 w-full rounded-control border border-border bg-white px-2.5 text-fg focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-accent";

export function ImportDialog({ open, onOpenChange, project, env, onImported }: Props) {
  const qc = useQueryClient();
  const toast = useToast();
  const [step, setStep] = useState<Step>("source");
  const [source, setSource] = useState<"upload" | "paste">("upload");
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [targetProject, setTargetProject] = useState(project);
  const [newProject, setNewProject] = useState("");
  const [targetEnv, setTargetEnv] = useState(env);
  const [newEnv, setNewEnv] = useState("");
  const [mode, setMode] = useState<"merge" | "replace">("merge");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [resolutions, setResolutions] = useState<Record<string, Resolution>>({});
  const [types, setTypes] = useState<Record<string, VariableType>>({});
  const [ackReplace, setAckReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  // Clear everything, including the pasted/uploaded content, on close.
  useEffect(() => {
    if (open) {
      setTargetProject(project);
      setTargetEnv(env);
      return;
    }
    setStep("source");
    setContent("");
    setFileName(null);
    setPreview(null);
    setResolutions({});
    setTypes({});
    setAckReplace(false);
    setMode("merge");
    setNewProject("");
    setNewEnv("");
    setError(null);
  }, [open, project, env]);

  const projects = useQuery({ queryKey: ["projects", ""], queryFn: () => api.projects(), enabled: open });
  const envs = useQuery({
    queryKey: ["project", targetProject],
    queryFn: () => api.project(targetProject),
    enabled: open && targetProject !== NEW && !!targetProject,
  });

  const projectRef = targetProject === NEW ? newProject.trim() : targetProject;
  const envRef = targetProject === NEW || targetEnv === NEW ? newEnv.trim() : targetEnv;

  async function readFile(file: File) {
    setError(null);
    if (file.size > MAX_BYTES) {
      setError("The file is larger than the 1 MiB import limit.");
      return;
    }
    setContent(await file.text());
    setFileName(file.name);
  }

  async function runPreview() {
    setError(null);
    if (!content.trim()) {
      setError(source === "upload" ? "Choose a .env file first." : "Paste dotenv contents first.");
      return;
    }
    if (new Blob([content]).size > MAX_BYTES) {
      setError("The content is larger than the 1 MiB import limit.");
      return;
    }
    if (!projectRef || !envRef) {
      setError("Choose a target project and environment.");
      return;
    }
    setBusy(true);
    try {
      const p = await api.importPreview({ project: projectRef, environment: envRef, content, mode });
      setPreview(p);
      setResolutions({});
      setTypes({});
      setAckReplace(false);
      setStep("preview");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const plan = preview?.plan;
  const errors = preview?.issues.filter((i) => i.severity === "error") ?? [];
  const warnings = preview?.issues.filter((i) => i.severity === "warning") ?? [];
  const conflicts = useMemo(() => plan?.items.filter((i) => i.status === "changed") ?? [], [plan]);
  const unresolved = conflicts.filter((c) => !resolutions[c.key]).length;

  const summary = useMemo(() => {
    const s = { created: 0, overwrite: 0, keep: 0, unchanged: 0, removed: 0 };
    for (const it of plan?.items ?? []) {
      if (it.status === "new") s.created++;
      else if (it.status === "unchanged") s.unchanged++;
      else if (it.status === "removed") s.removed++;
      else if (resolutions[it.key] === "overwrite") s.overwrite++;
      else s.keep++;
    }
    return s;
  }, [plan, resolutions]);

  async function commit() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.importCommit({
        project: projectRef,
        environment: envRef,
        content,
        mode,
        resolutions,
        types,
        confirmReplace: mode === "replace" && ackReplace,
        createMissing: !preview.target.projectExists || !preview.target.environmentExists,
      });
      const r = res.result;
      toast.success(`Imported: ${r.created} created, ${r.updated} updated, ${r.kept} kept, ${r.removed} removed`);
      qc.invalidateQueries({ queryKey: ["projects"] });
      qc.invalidateQueries({ queryKey: ["project"] });
      qc.invalidateQueries({ queryKey: ["variables"] });
      qc.invalidateQueries({ queryKey: ["text-values"] });
      onImported(res.projectSlug, res.environmentSlug);
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e) + " Nothing was changed.");
    } finally {
      setBusy(false);
    }
  }

  const footer =
    step === "source" ? (
      <>
        <Button onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button variant="primary" loading={busy} onClick={runPreview}>
          Preview import
        </Button>
      </>
    ) : step === "preview" ? (
      <>
        <Button onClick={() => setStep("source")}>Back</Button>
        <Button
          variant="primary"
          disabled={!plan || errors.length > 0 || unresolved > 0 || (mode === "replace" && plan.counts.removed > 0 && !ackReplace)}
          onClick={() => setStep("confirm")}
        >
          Continue
        </Button>
      </>
    ) : (
      <>
        <Button onClick={() => setStep("preview")}>Back</Button>
        <Button variant={summary.removed > 0 ? "danger" : "primary"} loading={busy} onClick={commit}>
          Confirm import
        </Button>
      </>
    );

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Import variables"
      description={step === "source" ? "Upload a .env file or paste its contents. Nothing is written until you confirm." : `Target: ${projectRef} / ${envRef}`}
      footer={footer}
    >
      <ol className="mb-4 flex gap-4 text-[12.5px]" aria-label="Import steps">
        {(["source", "preview", "confirm"] as const).map((s, i) => (
          <li key={s} aria-current={step === s ? "step" : undefined} className={cn(step === s ? "font-semibold text-accent" : "text-muted")}>
            {i + 1}. {s === "source" ? "Source" : s === "preview" ? "Preview" : "Confirm"}
          </li>
        ))}
      </ol>

      {step === "source" && (
        <div className="flex flex-col gap-5">
          <Tabs.Root value={source} onValueChange={(v) => setSource(v as "upload" | "paste")}>
            <Tabs.List aria-label="Import source" className="mb-3 flex gap-1 border-b border-border">
              {(["upload", "paste"] as const).map((t) => (
                <Tabs.Trigger
                  key={t}
                  value={t}
                  className="-mb-px border-b-2 border-transparent px-3 py-2 text-[13.5px] font-medium text-muted hover:text-fg data-[state=active]:border-accent data-[state=active]:text-accent"
                >
                  {t === "upload" ? "Upload file" : "Paste contents"}
                </Tabs.Trigger>
              ))}
            </Tabs.List>
            <Tabs.Content value="upload">
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  const f = e.dataTransfer.files[0];
                  if (f) void readFile(f);
                }}
                className={cn(
                  "flex flex-col items-center gap-2 rounded-panel border border-dashed px-4 py-8 text-center",
                  dragging ? "border-accent bg-accent-soft" : "border-border bg-surface",
                )}
              >
                <FileUp size={20} aria-hidden className="text-muted" />
                <p className="text-[13.5px]">{fileName ? <>Selected <code>{fileName}</code></> : "Drag and drop a .env file here"}</p>
                <input
                  ref={fileInput}
                  type="file"
                  className="sr-only"
                  aria-label="Choose a .env file"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) void readFile(f);
                    e.target.value = "";
                  }}
                />
                <Button size="sm" onClick={() => fileInput.current?.click()}>
                  {fileName ? "Choose another file" : "Choose file"}
                </Button>
              </div>
            </Tabs.Content>
            <Tabs.Content value="paste">
              <Field label="Dotenv contents" hint="KEY=value per line. Comments, export prefixes and quoted values are supported.">
                {(p) => (
                  <Textarea
                    {...p}
                    rows={8}
                    spellCheck={false}
                    autoComplete="off"
                    className="font-mono"
                    placeholder={"# Example\nAPI_URL=https://api.example.test\nAPI_TOKEN=..."}
                    value={content}
                    onChange={(e) => {
                      setContent(e.target.value);
                      setFileName(null);
                    }}
                  />
                )}
              </Field>
            </Tabs.Content>
          </Tabs.Root>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Project">
              {(p) => (
                <select {...p} className={selectCls} value={targetProject} onChange={(e) => { setTargetProject(e.target.value); setTargetEnv(""); }}>
                  {projects.data?.projects.map((pr) => (
                    <option key={pr.id} value={pr.slug}>
                      {pr.name}
                    </option>
                  ))}
                  <option value={NEW}>New project…</option>
                </select>
              )}
            </Field>
            <Field label="Environment">
              {(p) =>
                targetProject === NEW ? (
                  <Input {...p} placeholder="development" value={newEnv} onChange={(e) => setNewEnv(e.target.value)} />
                ) : (
                  <select {...p} className={selectCls} value={targetEnv} onChange={(e) => setTargetEnv(e.target.value)}>
                    <option value="" disabled>
                      Choose…
                    </option>
                    {envs.data?.environments.map((en) => (
                      <option key={en.id} value={en.slug}>
                        {en.name}
                      </option>
                    ))}
                    <option value={NEW}>New environment…</option>
                  </select>
                )
              }
            </Field>
            {targetProject === NEW && (
              <Field label="New project name">{(p) => <Input {...p} value={newProject} onChange={(e) => setNewProject(e.target.value)} />}</Field>
            )}
            {targetProject !== NEW && targetEnv === NEW && (
              <Field label="New environment name">{(p) => <Input {...p} value={newEnv} onChange={(e) => setNewEnv(e.target.value)} />}</Field>
            )}
          </div>

          <fieldset>
            <legend className="mb-2 text-[13px] font-medium">Mode</legend>
            <div className="flex flex-col gap-2 text-[13.5px]">
              <label className="flex items-start gap-2">
                <input type="radio" name="mode" className="mt-1 accent-accent" checked={mode === "merge"} onChange={() => setMode("merge")} />
                <span>
                  <strong className="font-medium">Merge</strong> <span className="text-muted">(default) — add new keys and update changed ones; other variables stay.</span>
                </span>
              </label>
              <label className="flex items-start gap-2">
                <input type="radio" name="mode" className="mt-1 accent-accent" checked={mode === "replace"} onChange={() => setMode("replace")} />
                <span>
                  <strong className="font-medium">Replace</strong> <span className="text-muted">— make the environment match the input; variables not in it are removed.</span>
                </span>
              </label>
            </div>
          </fieldset>
        </div>
      )}

      {step === "preview" && preview && (
        <div className="flex flex-col gap-4">
          {(!preview.target.projectExists || !preview.target.environmentExists) && (
            <Alert tone="info" title="Will create">
              {!preview.target.projectExists ? `project “${projectRef}” with environment “${envRef}”` : `environment “${envRef}”`} when you confirm.
            </Alert>
          )}
          {errors.length > 0 && (
            <Alert tone="danger" title={`${errors.length} error${errors.length > 1 ? "s" : ""}`}>
              Fix these lines and preview again. Nothing will be imported.
            </Alert>
          )}
          {preview.issues.length > 0 && (
            <ul className="max-h-40 overflow-y-auto rounded-panel border border-border text-[13px]" aria-label="Parsing feedback">
              {[...errors, ...warnings].map((i, n) => (
                <li key={n} className="flex gap-3 border-b border-border px-3 py-1.5 last:border-0">
                  <span className={cn("w-16 shrink-0 font-medium", i.severity === "error" ? "text-danger" : "text-warning")}>
                    {i.severity === "error" ? "Error" : "Warning"}
                  </span>
                  <span className="w-16 shrink-0 text-muted tabular-nums">Line {i.line}</span>
                  <span className="min-w-0">{i.message}</span>
                </li>
              ))}
            </ul>
          )}
          {plan && (
            <>
              <div className="flex flex-wrap items-center gap-2 text-[13px]">
                <Badge tone="success">{plan.counts.new} new</Badge>
                <Badge tone="warning">{plan.counts.changed} changed</Badge>
                <Badge>{plan.counts.unchanged} unchanged</Badge>
                {plan.mode === "replace" && <Badge tone="danger">{plan.counts.removed} to remove</Badge>}
                {conflicts.length > 0 && (
                  <span className="ml-auto flex gap-2">
                    <Button size="sm" onClick={() => setResolutions(Object.fromEntries(conflicts.map((c) => [c.key, "overwrite"])))}>
                      Overwrite all
                    </Button>
                    <Button size="sm" onClick={() => setResolutions(Object.fromEntries(conflicts.map((c) => [c.key, "keep"])))}>
                      Keep all existing
                    </Button>
                  </span>
                )}
              </div>
              {conflicts.length > 0 && unresolved > 0 && (
                <p className="text-[13px] text-warning">
                  Choose keep or overwrite for {unresolved} changed key{unresolved > 1 ? "s" : ""}.
                </p>
              )}
              <div className="max-h-[42dvh] overflow-auto rounded-panel border border-border">
                <table className="w-full min-w-[560px] text-left text-[13px]">
                  <thead className="sticky top-0 bg-surface text-muted">
                    <tr className="border-b border-border">
                      <th scope="col" className="h-9 px-3 font-medium">Key</th>
                      <th scope="col" className="h-9 w-28 px-3 font-medium">Status</th>
                      <th scope="col" className="h-9 w-32 px-3 font-medium">Type</th>
                      <th scope="col" className="h-9 w-48 px-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.items.map((it) => (
                      <tr key={it.key} className="border-b border-border last:border-0">
                        <td className="px-3 py-2 font-mono break-all">{it.key}</td>
                        <td className="px-3 py-2">
                          <Badge tone={it.status === "new" ? "success" : it.status === "changed" ? "warning" : it.status === "removed" ? "danger" : "neutral"}>
                            {it.status}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          {it.status === "new" ? (
                            <select
                              aria-label={`Type for ${it.key}`}
                              title={it.typeReason}
                              className="h-7 rounded-control border border-border bg-white px-1.5 text-[13px]"
                              value={types[it.key] ?? it.type}
                              onChange={(e) => setTypes({ ...types, [it.key]: e.target.value as VariableType })}
                            >
                              <option value="secret">secret</option>
                              <option value="text">text</option>
                            </select>
                          ) : (
                            <span className="text-muted">{it.type}</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {it.status === "changed" ? (
                            <div role="radiogroup" aria-label={`Conflict for ${it.key}`} className="flex gap-3">
                              {(["keep", "overwrite"] as const).map((r) => (
                                <label key={r} className="flex items-center gap-1.5">
                                  <input
                                    type="radio"
                                    name={`res-${it.key}`}
                                    className="accent-accent"
                                    checked={resolutions[it.key] === r}
                                    onChange={() => setResolutions({ ...resolutions, [it.key]: r })}
                                  />
                                  {r === "keep" ? "Keep existing" : "Overwrite"}
                                </label>
                              ))}
                            </div>
                          ) : (
                            <span className="text-muted">{it.status === "new" ? "Add" : it.status === "removed" ? "Remove" : "No change"}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {plan.mode === "replace" && plan.counts.removed > 0 && (
                <label className="flex items-start gap-2 rounded-panel border border-danger/25 bg-danger-soft px-3 py-2.5 text-[13px]">
                  <input type="checkbox" className="mt-0.5 h-4 w-4 accent-danger" checked={ackReplace} onChange={(e) => setAckReplace(e.target.checked)} />
                  <span>
                    I understand replace mode permanently removes {plan.counts.removed} variable{plan.counts.removed > 1 ? "s" : ""} not present in the input.
                  </span>
                </label>
              )}
            </>
          )}
        </div>
      )}

      {step === "confirm" && (
        <div className="flex flex-col gap-4 text-[13.5px]">
          <p>
            Import into <strong className="font-medium">{projectRef}</strong> / <strong className="font-medium">{envRef}</strong> in one transaction. If anything fails, nothing changes.
          </p>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-panel border border-border bg-surface px-4 py-3 sm:grid-cols-3">
            {[
              ["Create", summary.created],
              ["Overwrite", summary.overwrite],
              ["Keep existing", summary.keep],
              ["Unchanged", summary.unchanged],
              ["Remove", summary.removed],
            ].map(([label, n]) => (
              <div key={label as string} className="flex justify-between gap-3">
                <dt className="text-muted">{label}</dt>
                <dd className={cn("font-medium tabular-nums", label === "Remove" && (n as number) > 0 && "text-danger")}>{n}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      {error && (
        <div className="mt-4">
          <Alert tone="danger">{error}</Alert>
        </div>
      )}
    </Dialog>
  );
}
