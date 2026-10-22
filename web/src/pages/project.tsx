import { useDeferredValue, useEffect, useState } from "react";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCopy, Copy, Download, Eye, EyeOff, Pencil, Plus, Search, Trash2, Upload } from "lucide-react";
import { api, errorMessage, type Environment, type Project, type Variable } from "@/lib/api";
import { absoluteTime, cn, copyText, formatDotenvLine, relativeTime } from "@/lib/utils";
import { EmptyState, PageHeader } from "@/components/layout";
import { Button, IconButton } from "@/components/ui/button";
import { Alert, Badge, Field, Input, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";
import { ConfirmDialog, NameDialog } from "@/components/confirm";
import { VariableDialog } from "@/components/variable-dialog";
import { ImportDialog } from "@/components/import-dialog";

const route = getRouteApi("/projects/$projectSlug");
const REVEAL_MS = 30_000;

export function ProjectPage() {
  const { projectSlug } = route.useParams();
  const search = route.useSearch();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const query = useQuery({ queryKey: ["project", projectSlug], queryFn: () => api.project(projectSlug) });
  const [dialog, setDialog] = useState<null | "edit-project" | "delete-project" | "new-env" | "rename-env" | "delete-env" | "import">(null);

  if (query.isPending) return <p className="py-8 text-muted" aria-busy="true">Loading project…</p>;
  if (query.isError) {
    return (
      <EmptyState title="Project not available" action={<Link to="/projects" className="text-accent hover:underline">Back to projects</Link>}>
        {errorMessage(query.error)}
      </EmptyState>
    );
  }
  const { project, environments } = query.data;
  const current = environments.find((e) => e.slug === search.env) ?? environments[0];
  const selectEnv = (slug: string) => navigate({ to: "/projects/$projectSlug", params: { projectSlug }, search: { env: slug }, replace: true });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["project", projectSlug] });
    qc.invalidateQueries({ queryKey: ["projects"] });
  };

  return (
    <>
      <PageHeader
        eyebrow={
          <Link to="/projects" className="hover:text-fg hover:underline">
            Projects
          </Link>
        }
        title={project.name}
        description={project.description || <span className="italic">No description</span>}
        actions={
          <>
            <Button size="sm" onClick={() => setDialog("edit-project")}>
              <Pencil size={13} aria-hidden />
              Edit project
            </Button>
            <Button size="sm" variant="ghost" className="text-danger hover:text-danger" onClick={() => setDialog("delete-project")}>
              <Trash2 size={13} aria-hidden />
              Delete
            </Button>
          </>
        }
      />

      <div className="mb-5 flex items-end gap-1 overflow-x-auto overflow-y-hidden border-b border-border" role="tablist" aria-label="Environments">
        {environments.map((e) => (
          <button
            key={e.id}
            role="tab"
            aria-selected={current?.id === e.id}
            tabIndex={current?.id === e.id ? 0 : -1}
            onClick={() => selectEnv(e.slug)}
            onKeyDown={(ev) => {
              const i = environments.indexOf(e);
              const next = ev.key === "ArrowRight" ? environments[i + 1] : ev.key === "ArrowLeft" ? environments[i - 1] : undefined;
              if (next) {
                selectEnv(next.slug);
                (ev.currentTarget.parentElement?.children[environments.indexOf(next)] as HTMLElement | undefined)?.focus();
              }
            }}
            className={cn(
              "-mb-px flex h-10 shrink-0 items-center gap-2 border-b-2 px-3 text-[13.5px] font-medium",
              current?.id === e.id ? "border-accent text-accent" : "border-transparent text-muted hover:text-fg",
            )}
          >
            {e.name}
            <span className="rounded bg-surface px-1.5 text-xs text-muted tabular-nums">{e.variableCount}</span>
          </button>
        ))}
        <Button size="sm" variant="ghost" className="mb-1 ml-1" onClick={() => setDialog("new-env")}>
          <Plus size={14} aria-hidden />
          Environment
        </Button>
      </div>

      {current ? (
        <EnvironmentPanel
          key={current.id}
          project={project}
          env={current}
          onImport={() => setDialog("import")}
          onRename={() => setDialog("rename-env")}
          onDelete={() => setDialog("delete-env")}
        />
      ) : (
        <EmptyState title="No environments" action={<Button variant="primary" onClick={() => setDialog("new-env")}>Add environment</Button>}>
          Add an environment such as development or production to start storing variables.
        </EmptyState>
      )}

      <EditProjectDialog open={dialog === "edit-project"} onOpenChange={(o) => setDialog(o ? "edit-project" : null)} project={project} />
      <ConfirmDialog
        open={dialog === "delete-project"}
        onOpenChange={(o) => setDialog(o ? "delete-project" : null)}
        title={`Delete ${project.name}?`}
        confirmLabel="Delete project"
        typeToConfirm={project.slug}
        onConfirm={async () => {
          await api.deleteProject(project.slug);
          qc.removeQueries({ queryKey: ["project", project.slug] });
          qc.invalidateQueries({ queryKey: ["projects"] });
          toast.success(`Deleted ${project.name}`);
          navigate({ to: "/projects" });
        }}
      >
        This permanently deletes the project, its {environments.length} environment(s) and{" "}
        {environments.reduce((n, e) => n + e.variableCount, 0)} variable(s). This cannot be undone.
      </ConfirmDialog>
      <NameDialog
        open={dialog === "new-env"}
        onOpenChange={(o) => setDialog(o ? "new-env" : null)}
        title="Add environment"
        label="Environment name"
        hint="For example: preview, qa, production-eu"
        submitLabel="Add environment"
        onSubmit={async (name) => {
          const { environment } = await api.createEnvironment(project.slug, name);
          refresh();
          selectEnv(environment.slug);
          toast.success(`Added environment ${environment.name}`);
        }}
      />
      {current && (
        <>
          <NameDialog
            open={dialog === "rename-env"}
            onOpenChange={(o) => setDialog(o ? "rename-env" : null)}
            title={`Rename ${current.name}`}
            label="Environment name"
            initial={current.name}
            submitLabel="Rename"
            onSubmit={async (name) => {
              const { environment } = await api.renameEnvironment(project.slug, current.slug, name);
              refresh();
              selectEnv(environment.slug);
            }}
          />
          <ConfirmDialog
            open={dialog === "delete-env"}
            onOpenChange={(o) => setDialog(o ? "delete-env" : null)}
            title={`Delete ${current.name}?`}
            confirmLabel="Delete environment"
            typeToConfirm={current.slug}
            onConfirm={async () => {
              await api.deleteEnvironment(project.slug, current.slug);
              refresh();
              toast.success(`Deleted environment ${current.name}`);
              navigate({ to: "/projects/$projectSlug", params: { projectSlug }, search: {}, replace: true });
            }}
          >
            This permanently deletes the environment and its {current.variableCount} variable(s).
          </ConfirmDialog>
          <ImportDialog
            open={dialog === "import"}
            onOpenChange={(o) => setDialog(o ? "import" : null)}
            project={project.slug}
            env={current.slug}
            onImported={(p, e) => navigate({ to: "/projects/$projectSlug", params: { projectSlug: p }, search: { env: e } })}
          />
        </>
      )}
    </>
  );
}

function EditProjectDialog({ open, onOpenChange, project }: { open: boolean; onOpenChange: (o: boolean) => void; project: Project }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setName(project.name);
      setDescription(project.description);
      setError(null);
    }
  }, [open, project]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const { project: p } = await api.updateProject(project.slug, { name: name.trim(), description: description.trim() });
      qc.invalidateQueries({ queryKey: ["projects"] });
      qc.invalidateQueries({ queryKey: ["project", project.slug] });
      onOpenChange(false);
      if (p.slug !== project.slug) navigate({ to: "/projects/$projectSlug", params: { projectSlug: p.slug }, replace: true });
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
      title="Edit project"
      description="Renaming also changes the project slug used in CLI commands."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="edit-project" loading={busy}>
            Save
          </Button>
        </>
      }
    >
      <form
        id="edit-project"
        className="flex flex-col gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Field label="Name">{(p) => <Input {...p} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        <Field label="Description" optional>
          {(p) => <Textarea {...p} rows={2} maxLength={500} value={description} onChange={(e) => setDescription(e.target.value)} />}
        </Field>
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Dialog>
  );
}

function EnvironmentPanel({
  project,
  env,
  onImport,
  onRename,
  onDelete,
}: {
  project: Project;
  env: Environment;
  onImport: () => void;
  onRename: () => void;
  onDelete: () => void;
}) {
  const toast = useToast();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const q = useDeferredValue(search.trim());
  const [editing, setEditing] = useState<Variable | null | "new">(null);
  const [deleting, setDeleting] = useState<Variable | null>(null);
  const [exporting, setExporting] = useState(false);
  const [copyingAll, setCopyingAll] = useState(false);

  const vars = useQuery({
    queryKey: ["variables", project.slug, env.slug, q],
    queryFn: () => api.variables(project.slug, env.slug, q),
    placeholderData: (prev) => prev,
  });
  const list = vars.data?.variables ?? [];
  const hasText = list.some((v) => v.type === "text");
  // Text values are readable while unlocked; secrets are fetched per action.
  const textValues = useQuery({
    queryKey: ["text-values", project.slug, env.slug],
    queryFn: () => api.textValues(project.slug, env.slug),
    enabled: hasText,
    gcTime: 30_000,
  });

  async function copyAll() {
    setCopyingAll(true);
    try {
      const res = await api.exportEnvironment(project.slug, env.slug);
      await copyText(res.content);
      toast.success(`Copied ${res.count} variable(s) as dotenv`);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setCopyingAll(false);
    }
  }

  return (
    <section aria-label={`${env.name} variables`}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <label htmlFor="var-search" className="sr-only">
            Search variables
          </label>
          <Search size={14} aria-hidden className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted" />
          <Input id="var-search" type="search" placeholder="Search key or description" className="pl-8" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
          <Button size="sm" onClick={onImport}>
            <Upload size={13} aria-hidden />
            Import
          </Button>
          <Button size="sm" onClick={() => setExporting(true)} disabled={env.variableCount === 0}>
            <Download size={13} aria-hidden />
            Export
          </Button>
          <Button size="sm" onClick={copyAll} loading={copyingAll} disabled={env.variableCount === 0}>
            <ClipboardCopy size={13} aria-hidden />
            Copy all as .env
          </Button>
          <Button size="sm" variant="primary" onClick={() => setEditing("new")}>
            <Plus size={14} aria-hidden />
            Add variable
          </Button>
        </div>
      </div>

      {vars.isPending ? (
        <p className="py-8 text-muted" aria-busy="true">Loading variables…</p>
      ) : vars.isError ? (
        <Alert tone="danger">{errorMessage(vars.error)}</Alert>
      ) : list.length === 0 ? (
        q ? (
          <EmptyState title="No matching variables">No key or description matches “{q}”.</EmptyState>
        ) : (
          <EmptyState
            title={`${env.name} has no variables`}
            action={
              <div className="flex gap-2">
                <Button onClick={onImport}>
                  <Upload size={14} aria-hidden />
                  Import .env
                </Button>
                <Button variant="primary" onClick={() => setEditing("new")}>
                  <Plus size={14} aria-hidden />
                  Add variable
                </Button>
              </div>
            }
          >
            Add variables one by one or import an existing dotenv file.
          </EmptyState>
        )
      ) : (
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="w-full min-w-[600px] table-fixed border-collapse text-left">
            <thead className="bg-surface text-[12.5px] text-muted">
              <tr className="border-b border-border">
                <th scope="col" className="h-10 w-[32%] px-4 font-medium">Key</th>
                <th scope="col" className="h-10 px-4 font-medium">Value</th>
                <th scope="col" className="h-10 w-20 px-3 font-medium">Type</th>
                <th scope="col" className="hidden h-10 w-28 px-3 font-medium lg:table-cell">Updated</th>
                <th scope="col" className="h-10 w-[176px] px-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.map((v) => (
                <VariableRow
                  key={v.id}
                  variable={v}
                  textValue={v.type === "text" ? textValues.data?.values[v.id] : undefined}
                  textLoading={v.type === "text" && textValues.isPending}
                  onEdit={() => setEditing(v)}
                  onDelete={() => setDeleting(v)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 flex gap-4 text-[13px]">
        <button className="text-muted hover:text-fg hover:underline" onClick={onRename}>
          Rename environment
        </button>
        <button className="text-danger hover:underline" onClick={onDelete}>
          Delete environment
        </button>
      </div>

      <VariableDialog
        open={editing !== null}
        onOpenChange={(o) => !o && setEditing(null)}
        project={project.slug}
        env={env.slug}
        variable={editing && editing !== "new" ? editing : undefined}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.key}?`}
        confirmLabel="Delete variable"
        onConfirm={async () => {
          if (!deleting) return;
          await api.deleteVariable(deleting.id);
          qc.invalidateQueries({ queryKey: ["variables", project.slug, env.slug] });
          qc.invalidateQueries({ queryKey: ["text-values", project.slug, env.slug] });
          qc.invalidateQueries({ queryKey: ["project", project.slug] });
          toast.success(`Deleted ${deleting.key}`);
        }}
      >
        <span className="font-mono">{deleting?.key}</span> will be removed from {project.name} / {env.name}.
      </ConfirmDialog>
      <ExportDialog open={exporting} onOpenChange={setExporting} project={project} env={env} />
    </section>
  );
}

function VariableRow({
  variable: v,
  textValue,
  textLoading,
  onEdit,
  onDelete,
}: {
  variable: Variable;
  textValue?: string;
  textLoading: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const toast = useToast();
  const [revealed, setRevealed] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Revealed secrets live only in this row's state and hide themselves.
  useEffect(() => {
    if (revealed === null) return;
    const t = window.setTimeout(() => setRevealed(null), REVEAL_MS);
    return () => window.clearTimeout(t);
  }, [revealed]);
  useEffect(() => setRevealed(null), [v.updatedAt]);

  async function value(): Promise<string> {
    if (v.type === "text" && textValue !== undefined) return textValue;
    return (await api.reveal(v.id)).value;
  }

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const shown = v.type === "text" ? textValue : revealed;
  return (
    <tr className="h-12 border-b border-border last:border-0 hover:bg-surface/70">
      <td className="px-4 py-1.5 align-middle">
        <div className="font-mono text-[12.5px] font-medium break-all text-fg">{v.key}</div>
        {v.description && <div className="line-clamp-1 text-[12.5px] text-muted">{v.description}</div>}
      </td>
      <td className="max-w-0 px-4 py-1.5 align-middle">
        {shown !== undefined && shown !== null ? (
          <code className="block truncate text-fg" title={v.type === "text" ? shown : undefined}>
            {shown === "" ? <span className="text-muted italic">empty</span> : shown}
          </code>
        ) : v.type === "text" && textLoading ? (
          <span className="text-muted">Loading…</span>
        ) : (
          <span className="font-mono tracking-widest text-muted" aria-label="Hidden value">
            ••••••••••
          </span>
        )}
      </td>
      <td className="px-3 py-1.5 align-middle">
        <Badge tone={v.type === "secret" ? "accent" : "neutral"}>{v.type}</Badge>
      </td>
      <td className="hidden px-3 py-1.5 align-middle text-[13px] text-muted lg:table-cell">
        <time dateTime={v.updatedAt} title={absoluteTime(v.updatedAt)}>
          {relativeTime(v.updatedAt)}
        </time>
      </td>
      <td className="px-2 py-1.5 align-middle">
        <div className="flex items-center justify-end">
          {v.type === "secret" &&
            (revealed !== null ? (
              <IconButton label={`Hide ${v.key}`} icon={<EyeOff size={15} aria-hidden />} onClick={() => setRevealed(null)} />
            ) : (
              <IconButton
                label={`Reveal ${v.key}`}
                icon={<Eye size={15} aria-hidden />}
                disabled={busy}
                onClick={() => run(async () => setRevealed((await api.reveal(v.id)).value))}
              />
            ))}
          <IconButton
            label={`Copy value of ${v.key}`}
            icon={<Copy size={15} aria-hidden />}
            disabled={busy}
            onClick={() =>
              run(async () => {
                await copyText(await value());
                toast.success(`Copied ${v.key} value`);
              })
            }
          />
          <Button
            size="sm"
            variant="ghost"
            className="px-2 font-mono text-[12px]"
            aria-label={`Copy ${v.key}=value line`}
            title="Copy KEY=value"
            disabled={busy}
            onClick={() =>
              run(async () => {
                await copyText(formatDotenvLine(v.key, await value()));
                toast.success(`Copied ${v.key}=…`);
              })
            }
          >
            K=V
          </Button>
          <IconButton label={`Edit ${v.key}`} icon={<Pencil size={14} aria-hidden />} onClick={onEdit} />
          <IconButton label={`Delete ${v.key}`} icon={<Trash2 size={14} aria-hidden />} className="hover:text-danger" onClick={onDelete} />
        </div>
      </td>
    </tr>
  );
}

function ExportDialog({ open, onOpenChange, project, env }: { open: boolean; onOpenChange: (o: boolean) => void; project: Project; env: Environment }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const filename = `.env.${project.slug}.${env.slug}`;

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.exportEnvironment(project.slug, env.slug);
      const url = URL.createObjectURL(new Blob([res.content], { type: "text/plain;charset=utf-8" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = res.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      // Release the blob promptly so the plaintext does not linger.
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast.success(`Downloaded ${res.count} variable(s)`);
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
      onOpenChange={(o) => {
        setError(null);
        onOpenChange(o);
      }}
      size="sm"
      title="Export environment"
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" loading={busy} onClick={download}>
            <Download size={14} aria-hidden />
            Download .env
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-[13.5px]">
        <dl className="grid grid-cols-[110px_1fr] gap-y-1.5">
          <dt className="text-muted">Project</dt>
          <dd>{project.name}</dd>
          <dt className="text-muted">Environment</dt>
          <dd>{env.name}</dd>
          <dt className="text-muted">Variables</dt>
          <dd className="tabular-nums">{env.variableCount}</dd>
          <dt className="text-muted">File name</dt>
          <dd className="font-mono">{filename}</dd>
        </dl>
        <Alert tone="warning" title="Plaintext file">
          The downloaded dotenv file contains every value unencrypted. Keep it out of version control and delete it when you are done.
        </Alert>
        <p className="text-[13px] text-muted">
          From a terminal: <code>ven export -p {project.slug} -e {env.slug} --out .env</code>
        </p>
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
    </Dialog>
  );
}
