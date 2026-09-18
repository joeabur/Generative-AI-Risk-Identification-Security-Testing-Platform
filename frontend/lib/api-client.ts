"use client";

import { PUBLIC_API_BASE_URL } from "./config";
import { ApiError } from "./errors";
import type { ApiErrorBody } from "./types";

/**
 * Browser-side fetch helper. `credentials: "include"` sends the
 * httpOnly session cookie the backend set on login/register — this file
 * never touches the token itself, it relies entirely on the cookie.
 */
export async function clientApiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
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
