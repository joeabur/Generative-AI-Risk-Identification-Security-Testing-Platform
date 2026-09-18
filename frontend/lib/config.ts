/**
 * The backend is reached by two different names depending on where the code
 * runs: server components/route handlers run inside the Docker network and
 * talk to the `backend` service directly, while the browser only ever knows
 * about the publicly exposed URL. Both must point at the same backend.
 */
export const SERVER_API_BASE_URL =
  process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8000/api/v1";

export const PUBLIC_API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export const SESSION_COOKIE_NAME = "aegis_session";
