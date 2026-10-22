import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, onAuthLost, setCsrfToken, type SessionState } from "./api";

export type Phase = "loading" | "no-session" | "setup" | "locked" | "unlocked" | "error";

interface SessionContextValue {
  phase: Phase;
  state: SessionState | null;
  /** Increments whenever sensitive state must be discarded (lock, expiry). */
  epoch: number;
  error: string | null;
  apply: (s: SessionState) => void;
  lock: () => Promise<void>;
  setAutoLockMinutes: (n: number) => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

// The launch token is kept in memory only: read once from the URL fragment
// (which browsers never send to servers), then removed from the address bar.
let launchToken = "";
function takeLaunchToken() {
  const m = window.location.hash.match(/(?:^#|&)launch=([0-9a-f]{64})/);
  if (m) {
    launchToken = m[1]!;
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
}

function phaseOf(s: SessionState): Phase {
  if (!s.authenticated) return "no-session";
  if (!s.initialized) return "setup";
  return s.unlocked ? "unlocked" : "locked";
}

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart", "mousemove"] as const;

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<SessionState | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [epoch, setEpoch] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const phaseRef = useRef<Phase>("loading");
  const lastActivity = useRef(Date.now());
  const lastHeartbeat = useRef(Date.now());

  const purge = useCallback(() => {
    // Drop every cached response and remount the app so component state
    // (revealed values, form inputs) is discarded too.
    queryClient.cancelQueries();
    queryClient.clear();
    setEpoch((e) => e + 1);
  }, [queryClient]);

  const apply = useCallback(
    (s: SessionState) => {
      setCsrfToken(s.csrfToken);
      const next = phaseOf(s);
      if (phaseRef.current === "unlocked" && next !== "unlocked") purge();
      phaseRef.current = next;
      setState(s);
      setPhase(next);
      if (next === "unlocked") lastActivity.current = Date.now();
    },
    [purge],
  );

  const bootstrap = useCallback(async () => {
    try {
      let s = await api.session();
      if (!s.authenticated && launchToken) s = await api.createSession(launchToken);
      apply(s);
      setError(null);
    } catch (e) {
      if (phaseRef.current === "unlocked") purge();
      phaseRef.current = "no-session";
      setPhase(launchToken ? "error" : "no-session");
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [apply, purge]);

  useEffect(() => {
    takeLaunchToken();
    void bootstrap();
  }, [bootstrap]);

  // Any API response saying "locked" or "no session" clears sensitive state.
  useEffect(() => {
    onAuthLost((code) => {
      if (phaseRef.current === "unlocked") purge();
      if (code === "locked") {
        phaseRef.current = "locked";
        setPhase("locked");
        setState((s) => (s ? { ...s, unlocked: false } : s));
      } else {
        setCsrfToken("");
        void bootstrap();
      }
    });
    return () => onAuthLost(() => {});
  }, [bootstrap, purge]);

  const lock = useCallback(async () => {
    purge();
    try {
      apply(await api.lock());
    } catch {
      void bootstrap();
    }
  }, [apply, bootstrap, purge]);

  // Track activity; send heartbeats while active; lock locally when idle.
  useEffect(() => {
    if (phase !== "unlocked") return;
    const mark = () => {
      lastActivity.current = Date.now();
    };
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, mark, { passive: true });
    const timer = window.setInterval(() => {
      const minutes = state?.autoLockMinutes ?? 15;
      const idle = Date.now() - lastActivity.current;
      if (idle >= minutes * 60_000) {
        void lock();
        return;
      }
      if (lastActivity.current > lastHeartbeat.current && Date.now() - lastHeartbeat.current > 60_000) {
        lastHeartbeat.current = Date.now();
        api.heartbeat().catch(() => {});
      }
    }, 5_000);
    // Poll session state so a server-side lock (auto-lock sweep, `ven ui`
    // restart) is noticed even without user actions.
    const poll = window.setInterval(() => {
      api.session().then(apply, () => void bootstrap());
    }, 20_000);
    return () => {
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, mark);
      window.clearInterval(timer);
      window.clearInterval(poll);
    };
  }, [phase, state?.autoLockMinutes, lock, apply, bootstrap]);

  const setAutoLockMinutes = useCallback((n: number) => {
    setState((s) => (s ? { ...s, autoLockMinutes: n } : s));
  }, []);

  const value = useMemo(
    () => ({ phase, state, epoch, error, apply, lock, setAutoLockMinutes }),
    [phase, state, epoch, error, apply, lock, setAutoLockMinutes],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
