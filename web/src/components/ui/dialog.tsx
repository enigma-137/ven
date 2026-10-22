import type { ReactNode } from "react";
import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
}

/** Accessible modal (focus trap, Escape to close, labelled by title). */
export function Dialog({ open, onOpenChange, title, description, children, footer, size = "md" }: DialogProps) {
  const width = { sm: "max-w-md", md: "max-w-lg", lg: "max-w-3xl" }[size];
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-fg/30" />
        <D.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-50 flex max-h-[calc(100dvh-32px)] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 flex-col",
            "rounded-panel border border-border bg-white shadow-[0_8px_30px_rgba(24,24,27,0.12)] focus:outline-none",
            width,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <D.Title className="text-[15px] font-semibold text-fg">{title}</D.Title>
              {description ? (
                <D.Description className="mt-1 text-[13px] text-muted">{description}</D.Description>
              ) : (
                <D.Description className="sr-only">{title}</D.Description>
              )}
            </div>
            <D.Close
              aria-label="Close dialog"
              className="-mr-1 rounded-control p-1 text-muted hover:bg-surface hover:text-fg focus-visible:outline-2 focus-visible:outline-accent"
            >
              <X size={16} aria-hidden />
            </D.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-border bg-surface px-5 py-3">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
