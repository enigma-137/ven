// Typed client for the VEN local API. The CSRF token lives only in memory;
// nothing here touches localStorage, sessionStorage or URLs with secrets.

export type VariableType = "secret" | "text";

export interface SessionState {
  authenticated: boolean;
  csrfToken?: string;
  initialized: boolean;
  unlocked: boolean;
  autoLockMinutes: number;
  version: string;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  description: string;
  environmentCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface Environment {
  id: string;
  name: string;
  slug: string;
  variableCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface Variable {
  id: string;
  environmentId: string;
  key: string;
  type: VariableType;
  description: string;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

export interface Settings {
  vaultPath: string;
  autoLockMinutes: number;
  version: string;
  schemaVersion: number;
  kdf: { algorithm: string; memoryKiB: number; iterations: number; parallelism: number };
}

export interface ParseIssue {
  line: number;
  severity: "error" | "warning";
  message: string;
}

export type ChangeStatus = "new" | "changed" | "unchanged" | "removed";

export interface PlanItem {
  key: string;
  status: ChangeStatus;
  line?: number;
  type: VariableType;
  typeReason?: string;
  existingType?: VariableType;
}

export interface ImportPlan {
  mode: "merge" | "replace";
  items: PlanItem[];
  counts: { new: number; changed: number; unchanged: number; removed: number };
}

export interface ImportPreview {
  issues: ParseIssue[];
  target: { projectExists: boolean; environmentExists: boolean; projectSlug: string; environmentSlug: string };
  variableCount: number;
  plan?: ImportPlan;
}

export interface ImportResult {
  result: { created: number; updated: number; kept: number; unchanged: number; removed: number };
  projectSlug: string;
  environmentSlug: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public body?: unknown,
  ) {
    super(message);
  }
}

let csrfToken = "";
type AuthListener = (code: "locked" | "no_session") => void;
let authListener: AuthListener | null = null;

export function setCsrfToken(token: string | undefined) {
  csrfToken = token ?? "";
}

/** Registers the handler for responses that mean "locked" or "no session". */
export function onAuthLost(fn: AuthListener) {
  authListener = fn;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    throw new ApiError(0, "network", "Cannot reach the VEN server. Is `ven ui` still running?");
  }
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // Non-JSON error page.
  }
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string } } | null)?.error;
    const code = err?.code ?? "http_" + res.status;
    if (res.status === 401 && (code === "locked" || code === "no_session")) {
      authListener?.(code);
    }
    throw new ApiError(res.status, code, err?.message ?? `Request failed (${res.status})`, data);
  }
  return data as T;
}

const enc = encodeURIComponent;
const envPath = (project: string, env: string) => `/api/projects/${enc(project)}/environments/${enc(env)}`;

export const api = {
  session: () => request<SessionState>("GET", "/api/session"),
  createSession: (launchToken: string) => request<SessionState>("POST", "/api/session", { launchToken }),
  heartbeat: () => request<void>("POST", "/api/session/heartbeat"),
  initVault: (password: string) => request<SessionState & { recoveryKey: string }>("POST", "/api/vault/init", { password }),
  unlock: (password: string) => request<SessionState>("POST", "/api/vault/unlock", { password }),
  lock: () => request<SessionState>("POST", "/api/vault/lock"),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>("POST", "/api/vault/password", { currentPassword, newPassword }),

  settings: () => request<Settings>("GET", "/api/settings"),
  updateSettings: (autoLockMinutes: number) => request<Settings>("PUT", "/api/settings", { autoLockMinutes }),

  projects: (q = "") => request<{ projects: Project[] }>("GET", "/api/projects" + (q ? `?q=${enc(q)}` : "")),
  project: (slug: string) => request<{ project: Project; environments: Environment[] }>("GET", `/api/projects/${enc(slug)}`),
  createProject: (name: string, description: string, environments: string[]) =>
    request<{ project: Project; environments: Environment[] }>("POST", "/api/projects", { name, description, environments }),
  updateProject: (slug: string, patch: { name?: string; description?: string }) =>
    request<{ project: Project }>("PATCH", `/api/projects/${enc(slug)}`, patch),
  deleteProject: (slug: string) => request<void>("DELETE", `/api/projects/${enc(slug)}`, { confirm: slug }),

  createEnvironment: (project: string, name: string) =>
    request<{ environment: Environment }>("POST", `/api/projects/${enc(project)}/environments`, { name }),
  renameEnvironment: (project: string, env: string, name: string) =>
    request<{ environment: Environment }>("PATCH", envPath(project, env), { name }),
  deleteEnvironment: (project: string, env: string) => request<void>("DELETE", envPath(project, env), { confirm: env }),

  variables: (project: string, env: string, q = "") =>
    request<{ variables: Variable[] }>("GET", envPath(project, env) + "/variables" + (q ? `?q=${enc(q)}` : "")),
  textValues: (project: string, env: string) =>
    request<{ values: Record<string, string> }>("GET", envPath(project, env) + "/text-values"),
  createVariable: (project: string, env: string, v: { key: string; value: string; type: VariableType; description: string }) =>
    request<{ variable: Variable }>("POST", envPath(project, env) + "/variables", v),
  updateVariable: (id: string, patch: { key?: string; value?: string; type?: VariableType; description?: string }) =>
    request<{ variable: Variable }>("PATCH", `/api/variables/${enc(id)}`, patch),
  deleteVariable: (id: string) => request<void>("DELETE", `/api/variables/${enc(id)}`),
  reveal: (id: string) => request<{ id: string; key: string; value: string }>("POST", `/api/variables/${enc(id)}/reveal`),
  exportEnvironment: (project: string, env: string) =>
    request<{ filename: string; count: number; content: string }>("POST", envPath(project, env) + "/export"),

  importPreview: (body: { project: string; environment: string; content: string; mode: string }) =>
    request<ImportPreview>("POST", "/api/import/preview", body),
  importCommit: (body: {
    project: string;
    environment: string;
    content: string;
    mode: string;
    resolutions: Record<string, "keep" | "overwrite">;
    types: Record<string, VariableType>;
    confirmReplace: boolean;
    createMissing: boolean;
  }) => request<ImportResult>("POST", "/api/import/commit", body),
};

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong";
}
