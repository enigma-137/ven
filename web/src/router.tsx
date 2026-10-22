import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { Layout } from "@/components/layout";
import { ProjectsPage } from "@/pages/projects";
import { ProjectPage } from "@/pages/project";
import { SettingsPage } from "@/pages/settings";
import { NotFound } from "@/pages/not-found";

const rootRoute = createRootRoute({ component: Layout, notFoundComponent: NotFound });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => {
    throw redirect({ to: "/projects" });
  },
});

const projectsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/projects", component: ProjectsPage });

export interface ProjectSearch {
  env?: string;
}

const projectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/projects/$projectSlug",
  // Only the environment slug lives in the URL; never values.
  validateSearch: (search: Record<string, unknown>): ProjectSearch => ({
    env: typeof search.env === "string" && /^[a-z0-9-]{1,64}$/.test(search.env) ? search.env : undefined,
  }),
  component: ProjectPage,
});

const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings", component: SettingsPage });

const routeTree = rootRoute.addChildren([indexRoute, projectsRoute, projectRoute, settingsRoute]);

export function makeRouter() {
  return createRouter({ routeTree, defaultPreload: false });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof makeRouter>;
  }
}
