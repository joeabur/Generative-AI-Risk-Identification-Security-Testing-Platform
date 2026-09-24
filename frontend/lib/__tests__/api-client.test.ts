import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CSRF_HEADER_NAME, PUBLIC_API_BASE_URL } from "@/lib/config";

function mockFetchOnce(body: unknown = {}, init: ResponseInit = { status: 200 }) {
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      ...init,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("clientApiFetch CSRF header attachment", () => {
  beforeEach(() => {
    document.cookie = "aegis_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
    document.cookie = "aegis_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("attaches X-CSRF-Token on an unsafe method when the CSRF cookie is present", async () => {
    document.cookie = "aegis_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations", { method: "POST", body: JSON.stringify({ name: "x" }) });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${PUBLIC_API_BASE_URL}/organizations`);
    const headers = init.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("signed-token-value");
  });

  it("does not attach a CSRF header for safe methods, even with the cookie present", async () => {
    document.cookie = "aegis_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.has(CSRF_HEADER_NAME)).toBe(false);
  });

  it("omits the header on an unsafe method when there is no CSRF cookie yet", async () => {
    const fetchMock = mockFetchOnce({ ok: true });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/auth/login", { method: "POST", body: JSON.stringify({}) });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.has(CSRF_HEADER_NAME)).toBe(false);
  });

  it("does not override a caller-supplied CSRF header", async () => {
    document.cookie = "aegis_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations", {
      method: "POST",
      headers: { [CSRF_HEADER_NAME]: "caller-supplied" },
      body: JSON.stringify({ name: "x" }),
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("caller-supplied");
  });
});
