import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

type Tone = "success" | "error" | "info";
interface Toast {
  id: number;
  tone: Tone;
  message: string;
}

const ToastContext = createContext<(tone: Tone, message: string) => void>(() => {});

/** Minimal toasts announced through an aria-live region. Never pass values. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(0);
  const push = useCallback((tone: Tone, message: string) => {
    const id = ++next.current;
    setToasts((t) => [...t.slice(-3), { id, tone, message }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "error" ? 7000 : 3500);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div aria-live="polite" role="status" className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(360px,calc(100vw-32px))] flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              "pointer-events-auto rounded-panel border bg-white px-3.5 py-2.5 text-[13px] shadow-[0_4px_16px_rgba(24,24,27,0.10)]",
              t.tone === "error" ? "border-danger/30" : "border-border",
            )}
          >
            <span
              className={cn(
                "mr-1.5 font-semibold",
                t.tone === "success" && "text-success",
                t.tone === "error" && "text-danger",
                t.tone === "info" && "text-accent",
              )}
            >
              {t.tone === "success" ? "Done" : t.tone === "error" ? "Error" : "Note"}:
            </span>
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const push = useContext(ToastContext);
  return {
    success: (m: string) => push("success", m),
    error: (m: string) => push("error", m),
    info: (m: string) => push("info", m),
  };
}
