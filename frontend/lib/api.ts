export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input, API_URL);
  if (url.origin !== new URL(API_URL).origin) {
    throw new Error("Refusing to send credentials to another API origin.");
  }
  const headers = new Headers(init.headers);
  headers.set("X-AVIGHNA-Local-View", "1");
  const token = typeof window !== "undefined" ? window.localStorage.getItem("avighna_token") : null;
  if (token) headers.set("Authorization", "Bearer " + token);
  const response = await fetch(url.toString(), { ...init, headers });
  if (response.status === 401 && typeof window !== "undefined") {
    window.localStorage.removeItem("avighna_token");
    window.localStorage.removeItem("avighna_user");
    throw new Error("This operation requires authentication and is unavailable in local view.");
  }
  if (!response.ok) {
    let detail = "Request failed (" + response.status + ")";
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {}
    throw new Error(detail);
  }
  return response;
}
