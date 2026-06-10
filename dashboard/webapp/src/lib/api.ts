// Typed API client for VIPER backend
// All calls go through Next.js rewrites → localhost:8080

// Optional dashboard auth token. Sourced (in priority order) from a build-time
// env var or a runtime localStorage entry ("viper-token"). When set, it is sent
// as a Bearer header AND mirrored to a `viper_token` cookie so same-origin
// SSE/WebSocket streams authenticate too. Absent → no header (local-dev default).
const ENV_TOKEN =
  process.env.NEXT_PUBLIC_VIPER_DASHBOARD_TOKEN?.trim() || "";

function authToken(): string {
  if (ENV_TOKEN) return ENV_TOKEN;
  if (typeof window !== "undefined") {
    try {
      return window.localStorage.getItem("viper-token")?.trim() || "";
    } catch {
      return "";
    }
  }
  return "";
}

function authHeaders(base?: Record<string, string>): Record<string, string> {
  const h: Record<string, string> = { ...(base || {}) };
  const t = authToken();
  if (t) {
    h["Authorization"] = `Bearer ${t}`;
    // Mirror to a cookie for EventSource/WebSocket which can't set headers.
    if (typeof document !== "undefined" &&
        !document.cookie.includes("viper_token=")) {
      document.cookie = `viper_token=${t}; path=/; SameSite=Lax`;
    }
  }
  return h;
}

export async function apiGet<T>(path: string): Promise<T | null> {
  try {
    const r = await fetch(path, { headers: authHeaders() });
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

export async function apiPost<T>(
  path: string,
  body: Record<string, unknown>
): Promise<T | null> {
  try {
    const r = await fetch(path, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}
