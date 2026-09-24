"use client";

import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, PUBLIC_API_BASE_URL } from "./config";
import { ApiError } from "./errors";
import type { ApiErrorBody } from "./types";

/** Methods the backend's CSRF middleware treats as safe and never checks —
 * kept in sync with `SAFE_METHODS` in app/core/csrf/enforce.py. Anything else
 * sent with the session cookie needs the token attached below, or the
 * backend refuses it with 403 regardless of how valid the session is. */
const CSRF_SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

function readCookie(name: string): string | null {
  // SSR/server components have no `document`; those calls go through
  // lib/api-server.ts's `serverApiFetch`, which forwards the CSRF cookie
  // itself rather than reading it from a DOM this context does not have —
  // so returning null here is correct, not a fallback masking a bug.
  if (typeof document === "undefined") {
    return null;
  }
  const match = document.cookie.match(
    new RegExp(`(?:^|; )${name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1")}=([^;]*)`),
  );
  return match?.[1] !== undefined ? decodeURIComponent(match[1]) : null;
}

/**
 * Browser-side fetch helper. `credentials: "include"` sends the session
 * cookie the backend set on login/register.
 *
 * For any unsafe method the backend's CSRF middleware requires a matching
 * `X-CSRF-Token` header alongside that cookie (app/core/csrf/), because the
 * cookie alone is exactly what a forged cross-site request would also carry.
 * The token cookie is deliberately readable by this same-origin script (see
 * its own `httponly=False` on the backend) so it can be echoed here — an
 * attacker's page cannot read it, which is the whole point.
 *
 * A write made before any session exists (there is none today; see
 * docs/csrf.md's residual on login/registration) simply has no cookie to
 * read, so the header is omitted and the backend's own exemption for those
 * two paths is what makes the call succeed — this function does not decide
 * that, the backend does.
 */
export async function clientApiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const method = (init.method ?? "GET").toUpperCase();
  if (!CSRF_SAFE_METHODS.has(method) && !headers.has(CSRF_HEADER_NAME)) {
    const token = readCookie(CSRF_COOKIE_NAME);
    if (token) {
      headers.set(CSRF_HEADER_NAME, token);
    }
  }

  const response = await fetch(`${PUBLIC_API_BASE_URL}${path}`, {
    ...init,
    headers,
    credentials: "include",
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
