import { Link } from "@tanstack/react-router";
import { EmptyState } from "@/components/layout";

export function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      action={
        <Link to="/projects" className="text-accent hover:underline">
          Go to projects
        </Link>
      }
    />
  );
}
