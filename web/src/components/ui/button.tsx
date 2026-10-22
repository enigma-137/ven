import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md" | "icon";

const variants: Record<Variant, string> = {
  primary: "bg-accent text-white hover:bg-accent-hover border border-accent hover:border-accent-hover",
  secondary: "bg-white text-fg border border-border hover:bg-surface",
  ghost: "text-muted hover:text-fg hover:bg-surface border border-transparent",
  danger: "bg-danger text-white border border-danger hover:bg-danger-hover",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-2.5 gap-1.5 text-[13px]",
  md: "h-9 px-3.5 gap-2",
  icon: "h-8 w-8 justify-center",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, className, children, disabled, type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex shrink-0 items-center rounded-control font-medium whitespace-nowrap transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-55 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    >
      {loading && <Spinner className={variant === "primary" || variant === "danger" ? "text-white" : ""} />}
      {children}
    </button>
  );
});

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cn("inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-r-transparent text-muted", className)}
    />
  );
}

/** Icon-only button with an accessible label and a tooltip. */
export const IconButton = forwardRef<HTMLButtonElement, ButtonProps & { label: string; icon: ReactNode }>(function IconButton(
  { label, icon, variant = "ghost", ...props },
  ref,
) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <Button ref={ref} variant={variant} size="icon" aria-label={label} {...props}>
          {icon}
        </Button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          side="top"
          sideOffset={4}
          className="z-50 rounded-control bg-fg px-2 py-1 text-xs text-white shadow-sm"
        >
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
});
