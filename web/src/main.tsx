import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import * as Tooltip from "@radix-ui/react-tooltip";
import { ApiError } from "@/lib/api";
import { SessionProvider, useSession } from "@/lib/session";
import { makeRouter } from "@/router";
import { ToastProvider } from "@/components/ui/toast";
import { LoadingScreen, NoSessionScreen, SetupScreen, UnlockScreen } from "@/pages/auth";
import "./index.css";

// Query data is memory-only (no persister) and kept briefly.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      gcTime: 60_000,
      refetchOnWindowFocus: true,
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
    },
    mutations: { retry: false },
  },
});

function UnlockedApp({ epoch }: { epoch: number }) {
  // A new router per epoch remounts every page, discarding local state.
  const [router] = useState(makeRouter);
  return <RouterProvider key={epoch} router={router} />;
}

function Gate() {
  const { phase, epoch, error } = useSession();
  switch (phase) {
    case "loading":
      return <LoadingScreen />;
    case "no-session":
    case "error":
      return <NoSessionScreen error={phase === "error" ? error : null} />;
    case "setup":
      return <SetupScreen />;
    case "locked":
      return <UnlockScreen />;
    case "unlocked":
      return <UnlockedApp key={epoch} epoch={epoch} />;
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Tooltip.Provider delayDuration={300}>
        <ToastProvider>
          <SessionProvider>
            <Gate />
          </SessionProvider>
        </ToastProvider>
      </Tooltip.Provider>
    </QueryClientProvider>
  </StrictMode>,
);
