export const API_BASE = (process.env.NEXT_PUBLIC_BACKEND_URL || "/api").replace(/\/+$/, "");

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}
