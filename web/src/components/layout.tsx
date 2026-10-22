import { useState, type ReactNode } from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FolderKanban, Lock, Menu, Settings, X } from "lucide-react";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

function NavLink({ to, icon, children, active }: { to: string; icon: ReactNode; children: ReactNode; active: boolean }) {
  return (
    <Link
      to={to}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex h-8 items-center gap-2.5 rounded-control px-2.5 text-[13.5px] font-medium",
        active ? "bg-accent-soft text-accent" : "text-fg hover:bg-white",
      )}
    >
      {icon}
      {children}
    </Link>
  );
}

export function Layout() {
  const { lock, state } = useSession();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);
  const projects = useQuery({ queryKey: ["projects", ""], queryFn: () => api.projects() });

  const sidebar = (
    <nav aria-label="Main" className="flex h-full flex-col gap-5 p-3">
      <div className="flex items-center justify-between px-2.5 pt-1">
        <Link to="/projects" className="text-[19px] font-bold tracking-tight text-fg" onClick={() => setOpen(false)}>
          VEN
        </Link>
        <button className="rounded-control p-1 text-muted md:hidden" aria-label="Close navigation" onClick={() => setOpen(false)}>
          <X size={16} aria-hidden />
        </button>
      </div>
      <div className="flex flex-col gap-0.5" onClick={() => setOpen(false)}>
        <NavLink to="/projects" icon={<FolderKanban size={15} aria-hidden />} active={pathname === "/projects"}>
          Projects
        </NavLink>
        {projects.data && projects.data.projects.length > 0 && (
          <ul className="mt-1 mb-1 ml-[18px] flex flex-col gap-0.5 border-l border-border pl-2.5" aria-label="Projects">
            {projects.data.projects.slice(0, 12).map((p) => {
              const active = pathname === `/projects/${p.slug}`;
              return (
                <li key={p.id}>
                  <Link
                    to="/projects/$projectSlug"
                    params={{ projectSlug: p.slug }}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "block truncate rounded-control px-2 py-1 text-[13px]",
                      active ? "font-medium text-accent" : "text-muted hover:text-fg",
                    )}
                  >
                    {p.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
        <NavLink to="/settings" icon={<Settings size={15} aria-hidden />} active={pathname === "/settings"}>
          Settings
        </NavLink>
      </div>
      <div className="mt-auto flex flex-col gap-2 border-t border-border px-1 pt-3">
        <Button onClick={() => void lock()} className="justify-center">
          <Lock size={14} aria-hidden />
          Lock vault
        </Button>
        <p className="px-1 text-xs text-muted">
          Auto-locks after {state?.autoLockMinutes ?? 15} min of inactivity · v{state?.version}
        </p>
      </div>
    </nav>
  );

  return (
    <div className="flex min-h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-white focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 border-r border-border bg-surface md:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-fg/30" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-border bg-surface">{sidebar}</aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center gap-2 border-b border-border px-4 md:hidden">
          <button className="rounded-control p-1.5 text-fg hover:bg-surface" aria-label="Open navigation" onClick={() => setOpen(true)}>
            <Menu size={18} aria-hidden />
          </button>
          <span className="text-[17px] font-bold tracking-tight">VEN</span>
          <Button size="sm" className="ml-auto" onClick={() => void lock()}>
            <Lock size={13} aria-hidden />
            Lock
          </Button>
        </header>
        <main id="main" className="min-w-0 flex-1 px-4 py-6 md:px-8 md:py-7">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-[13px] text-muted">{eyebrow}</div>}
        <h1 className="text-[20px] leading-7 font-semibold tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-[13.5px] text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="rounded-panel border border-dashed border-border px-6 py-12 text-center">
      <h2 className="text-[15px] font-semibold">{title}</h2>
      {children && <div className="mx-auto mt-1.5 max-w-md text-[13.5px] text-muted">{children}</div>}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}
