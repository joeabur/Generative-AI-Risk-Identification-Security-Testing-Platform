import "server-only";

import { cookies } from "next/headers";

import { SERVER_API_BASE_URL, SESSION_COOKIE_NAME } from "./config";
import { ApiError } from "./errors";
import type { ApiErrorBody } from "./types";

/**
 * Server-side fetch helper for Server Components and Route Handlers.
 *
 * This forwards the caller's session cookie to the backend explicitly
 * (server-side `fetch` does not do this automatically) — the backend is the
 * only thing that ever decides whether the caller is authenticated or
 * authorized, per docs/BUILD_SPEC.md §17.2: "the frontend's role-based UI
 * hiding is cosmetic only."
 */
export async function serverApiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME);

  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (sessionCookie) {
    headers.set("Cookie", `${SESSION_COOKIE_NAME}=${sessionCookie.value}`);
  }

  const response = await fetch(`${SERVER_API_BASE_URL}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    const body = (await safeJson(response)) as Partial<ApiErrorBody> | null;
    throw new ApiError(response.status, body);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function isAuthenticated(): Promise<boolean> {
  const cookieStore = await cookies();
  return cookieStore.has(SESSION_COOKIE_NAME);
}
