import { useDeferredValue, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { absoluteTime, relativeTime } from "@/lib/utils";
import { EmptyState, PageHeader } from "@/components/layout";
import { Button } from "@/components/ui/button";
import { Alert, Field, Input, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";

export function ProjectsPage() {
  const [search, setSearch] = useState("");
  const q = useDeferredValue(search.trim());
  const [creating, setCreating] = useState(false);
  const projects = useQuery({ queryKey: ["projects", q], queryFn: () => api.projects(q), placeholderData: (prev) => prev });

  const list = projects.data?.projects ?? [];
  return (
    <>
      <PageHeader
        title="Projects"
        description="Each project holds environments such as development, staging and production, and their variables."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus size={15} aria-hidden />
            Create project
          </Button>
        }
      />
      <div className="mb-4 max-w-sm">
        <label htmlFor="project-search" className="sr-only">
          Search projects
        </label>
        <div className="relative">
          <Search size={14} aria-hidden className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted" />
          <Input id="project-search" type="search" placeholder="Search projects" className="pl-8" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      {projects.isPending ? (
        <p className="py-8 text-muted" aria-busy="true">
          Loading projects…
        </p>
      ) : projects.isError ? (
        <Alert tone="danger">
          {errorMessage(projects.error)}{" "}
          <button className="underline" onClick={() => projects.refetch()}>
            Retry
          </button>
        </Alert>
      ) : list.length === 0 ? (
        q ? (
          <EmptyState title="No matching projects">No project name or description matches “{q}”.</EmptyState>
        ) : (
          <EmptyState
            title="No projects yet"
            action={
              <Button variant="primary" onClick={() => setCreating(true)}>
                <Plus size={15} aria-hidden />
                Create project
              </Button>
            }
          >
            Create a project, then add variables or import an existing <code>.env</code> file. From a terminal:{" "}
            <code className="rounded bg-surface px-1 py-0.5">ven projects create my-app</code>
          </EmptyState>
        )
      ) : (
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="w-full min-w-[560px] border-collapse text-left">
            <thead className="bg-surface text-[12.5px] text-muted">
              <tr className="border-b border-border">
                <th scope="col" className="h-10 px-4 font-medium">Name</th>
                <th scope="col" className="h-10 w-36 px-4 font-medium">Environments</th>
                <th scope="col" className="h-10 w-40 px-4 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id} className="border-b border-border last:border-0 hover:bg-surface/70">
                  <td className="px-4 py-2.5">
                    <Link to="/projects/$projectSlug" params={{ projectSlug: p.slug }} className="font-medium text-fg hover:text-accent hover:underline">
                      {p.name}
                    </Link>
                    <span className="ml-2 font-mono text-xs text-muted">{p.slug}</span>
                    {p.description && <p className="mt-0.5 line-clamp-1 text-[13px] text-muted">{p.description}</p>}
                  </td>
                  <td className="px-4 py-2.5 text-muted tabular-nums">{p.environmentCount}</td>
                  <td className="px-4 py-2.5 text-muted">
                    <time dateTime={p.updatedAt} title={absoluteTime(p.updatedAt)}>
                      {relativeTime(p.updatedAt)}
                    </time>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateProjectDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

const DEFAULT_ENVS = ["development", "staging", "production"];

function slugify(s: string) {
  return s
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

export function CreateProjectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [envs, setEnvs] = useState<Record<string, boolean>>({ development: true, staging: true, production: true });
  const [custom, setCustom] = useState("");
  const [touched, setTouched] = useState(false);

  const customEnvs = custom
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const environments = [...DEFAULT_ENVS.filter((e) => envs[e]), ...customEnvs];
  const nameError = !name.trim() ? "Project name is required." : !slugify(name) ? "Use at least one letter or digit." : null;

  const create = useMutation({
    mutationFn: () => api.createProject(name.trim(), description.trim(), environments),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      toast.success(`Created project ${res.project.name}`);
      reset();
      onOpenChange(false);
      navigate({ to: "/projects/$projectSlug", params: { projectSlug: res.project.slug } });
    },
  });

  function reset() {
    setName("");
    setDescription("");
    setCustom("");
    setEnvs({ development: true, staging: true, production: true });
    setTouched(false);
    create.reset();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
      title="Create project"
      description="A project groups environments and their variables inside VEN. No files or code are created."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            variant="primary"
            type="submit"
            form="create-project"
            loading={create.isPending}
          >
            Create project
          </Button>
        </>
      }
    >
      <form
        id="create-project"
        className="flex flex-col gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (!nameError) create.mutate();
        }}
      >
        <Field label="Name" error={touched ? nameError : null} hint={name && slugify(name) ? <>Slug: <code>{slugify(name)}</code></> : "For example: Billing API"}>
          {(p) => <Input {...p} autoFocus value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label="Description" optional>
          {(p) => <Textarea {...p} rows={2} maxLength={500} value={description} onChange={(e) => setDescription(e.target.value)} />}
        </Field>
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1.5 text-[13px] font-medium">Environments</legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {DEFAULT_ENVS.map((env) => (
              <label key={env} className="flex items-center gap-2 text-[13.5px]">
                <input type="checkbox" className="h-4 w-4 accent-accent" checked={!!envs[env]} onChange={(e) => setEnvs({ ...envs, [env]: e.target.checked })} />
                {env}
              </label>
            ))}
          </div>
          <Field label="Custom environments" optional hint="Comma-separated, for example: preview, qa">
            {(p) => <Input {...p} value={custom} onChange={(e) => setCustom(e.target.value)} />}
          </Field>
        </fieldset>
        {create.isError && <Alert tone="danger">{errorMessage(create.error)}</Alert>}
      </form>
    </Dialog>
  );
}
