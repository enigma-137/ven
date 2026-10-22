import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const control =
  "w-full rounded-control border border-border bg-white px-3 text-fg placeholder:text-muted/70 " +
  "focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-accent " +
  "aria-[invalid=true]:border-danger disabled:bg-surface disabled:text-muted";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={cn(control, "h-9", className)} {...props} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea(
  { className, ...props },
  ref,
) {
  return <textarea ref={ref} className={cn(control, "min-h-20 py-2 leading-5", className)} {...props} />;
});

interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  optional?: boolean;
  children: (props: { id: string; "aria-describedby"?: string; "aria-invalid"?: boolean }) => ReactNode;
}

/** Label + control + hint/error, wired with ids for assistive tech. */
export function Field({ label, hint, error, optional, children }: FieldProps) {
  const id = useId();
  const descId = hint || error ? id + "-desc" : undefined;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] font-medium text-fg">
        {label}
        {optional && <span className="ml-1 font-normal text-muted">(optional)</span>}
      </label>
      {children({ id, "aria-describedby": descId, "aria-invalid": error ? true : undefined })}
      {error ? (
        <p id={descId} className="text-[13px] text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p id={descId} className="text-[13px] text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function Badge({ tone = "neutral", children }: { tone?: "neutral" | "accent" | "success" | "warning" | "danger"; children: ReactNode }) {
  const tones = {
    neutral: "bg-surface text-muted border-border",
    accent: "bg-accent-soft text-accent border-accent/20",
    success: "bg-success-soft text-success border-success/20",
    warning: "bg-warning-soft text-warning border-warning/20",
    danger: "bg-danger-soft text-danger border-danger/20",
  };
  return (
    <span className={cn("inline-flex h-5 items-center rounded-[4px] border px-1.5 text-xs font-medium", tones[tone])}>{children}</span>
  );
}

export function Alert({ tone, title, children }: { tone: "info" | "warning" | "danger" | "success"; title?: string; children?: ReactNode }) {
  const tones = {
    info: "border-accent/25 bg-accent-soft text-fg",
    warning: "border-warning/25 bg-warning-soft text-fg",
    danger: "border-danger/25 bg-danger-soft text-fg",
    success: "border-success/25 bg-success-soft text-fg",
  };
  const label = { info: "Note", warning: "Warning", danger: "Error", success: "Done" }[tone];
  const labelColor = { info: "text-accent", warning: "text-warning", danger: "text-danger", success: "text-success" }[tone];
  return (
    <div role={tone === "danger" ? "alert" : "status"} className={cn("rounded-panel border px-3 py-2.5 text-[13px] leading-5", tones[tone])}>
      <span className={cn("mr-1.5 font-semibold", labelColor)}>{title ?? label}:</span>
      {children}
    </div>
  );
}
