export interface User {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
}

export interface Options {
  devEmail?: string;
}

export const AUTH_ORIGIN = "https://auth.hanzpo.com";
export const COOKIE = "hanzpo_auth";

const enc = new TextEncoder();
const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIG = { name: "ECDSA", hash: "SHA-256" } as const;

export function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

export const decodeJson = <T = Record<string, unknown>>(s: string): T =>
  JSON.parse(new TextDecoder().decode(b64urlDecode(s))) as T;

export function readCookie(header: string | null, name: string): string | undefined {
  for (const part of (header ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

export async function verifyToken(
  token: string,
  getKey: (kid: string) => Promise<CryptoKey | undefined>,
  now = Date.now() / 1000,
): Promise<User | null> {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return null;
  try {
    const head = decodeJson<{ alg?: string; kid?: string }>(h);
    if (head.alg !== "ES256" || !head.kid) return null;
    const key = await getKey(head.kid);
    if (!key || !(await crypto.subtle.verify(SIG, key, b64urlDecode(s), enc.encode(`${h}.${p}`)))) return null;
    const c = decodeJson(p);
    if (c.iss !== AUTH_ORIGIN || typeof c.exp !== "number" || c.exp <= now) return null;
    if (typeof c.sub !== "string" || typeof c.email !== "string") return null;
    return {
      sub: c.sub,
      email: c.email,
      name: typeof c.name === "string" ? c.name : undefined,
      picture: typeof c.picture === "string" ? c.picture : undefined,
    };
  } catch {
    return null;
  }
}

let jwks: { keys: Map<string, CryptoKey>; fetched: number } | undefined;

async function remoteKey(kid: string): Promise<CryptoKey | undefined> {
  const now = Date.now();
  if (!jwks || (!jwks.keys.has(kid) && now - jwks.fetched > 60_000)) {
    const res = await fetch(`${AUTH_ORIGIN}/.well-known/jwks.json`);
    if (!res.ok) return jwks?.keys.get(kid);
    const { keys } = (await res.json()) as { keys: (JsonWebKey & { kid: string })[] };
    const map = new Map<string, CryptoKey>();
    for (const k of keys) map.set(k.kid, await crypto.subtle.importKey("jwk", k, ALG, false, ["verify"]));
    jwks = { keys: map, fetched: now };
  }
  return jwks.keys.get(kid);
}

export async function getUser(req: Request, opts: Options = {}): Promise<User | null> {
  const host = new URL(req.url).hostname;
  if (opts.devEmail && (host === "localhost" || host === "127.0.0.1")) return { sub: "dev", email: opts.devEmail };
  const token = readCookie(req.headers.get("cookie"), COOKIE);
  return token ? verifyToken(token, remoteKey) : null;
}

export const loginUrl = (returnTo: string) => `${AUTH_ORIGIN}/login?${new URLSearchParams({ return: returnTo })}`;
export const logoutUrl = (returnTo: string) => `${AUTH_ORIGIN}/logout?${new URLSearchParams({ return: returnTo })}`;

export async function requireUser(req: Request, opts: Options & { allow?: string[] } = {}): Promise<User | Response> {
  const user = await getUser(req, opts);
  if (!user) {
    return req.method === "GET" && req.headers.get("accept")?.includes("text/html")
      ? Response.redirect(loginUrl(req.url), 302)
      : new Response("Unauthorized", { status: 401 });
  }
  if (opts.allow && !opts.allow.some((e) => e.toLowerCase() === user.email.toLowerCase())) {
    return new Response("Forbidden", { status: 403 });
  }
  return user;
}
