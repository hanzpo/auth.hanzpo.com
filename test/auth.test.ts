import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import worker, { safeReturn, type Env } from "../src/index";
import { b64urlEncode, getUser, requireUser } from "../client/hanzpo-auth";

let env: Env;
const enc = new TextEncoder();
const b64json = (o: unknown) => b64urlEncode(enc.encode(JSON.stringify(o)));

beforeAll(async () => {
  const { privateKey } = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const { kty, crv, x, y, d } = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  env = {
    DOMAIN: "hanzpo.com",
    GOOGLE_CLIENT_ID: "client-123",
    GOOGLE_CLIENT_SECRET: "secret",
    SIGNING_KEY: JSON.stringify({ kty, crv, x, y, d, kid: "k1" }),
  };
});

afterEach(() => vi.unstubAllGlobals());

const call = (path: string, headers: Record<string, string> = {}) =>
  worker.fetch(new Request(`https://auth.hanzpo.com${path}`, { headers }), env);

const cookieValue = (res: Response, name: string) =>
  res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`))?.split(";")[0]!.slice(name.length + 1);

function stubGoogle(claims: Record<string, unknown>) {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const u = String(input);
    if (u === "https://oauth2.googleapis.com/token") {
      return Response.json({ id_token: `${b64json({ alg: "RS256" })}.${b64json(claims)}.sig` });
    }
    if (u === "https://auth.hanzpo.com/.well-known/jwks.json") return call("/.well-known/jwks.json");
    throw new Error(`unexpected fetch ${u}`);
  });
}

async function signIn(claimOverrides: Record<string, unknown> = {}, back = "https://foo.hanzpo.com/page?x=1") {
  const login = await call(`/login?return=${encodeURIComponent(back)}`);
  const google = new URL(login.headers.get("location")!);
  const stateCookie = cookieValue(login, "auth_state")!;
  stubGoogle({
    aud: "client-123",
    iss: "https://accounts.google.com",
    nonce: google.searchParams.get("nonce"),
    exp: Math.floor(Date.now() / 1000) + 600,
    email_verified: true,
    sub: "g-1",
    email: "me@example.com",
    name: "Me",
    ...claimOverrides,
  });
  return call(`/callback?code=abc&state=${google.searchParams.get("state")}`, { cookie: `auth_state=${stateCookie}` });
}

describe("safeReturn", () => {
  it("accepts hanzpo.com and its subdomains over https", () => {
    expect(safeReturn("https://hanzpo.com/", "hanzpo.com")).toBe("https://hanzpo.com/");
    expect(safeReturn("https://a.b.hanzpo.com/x?y=1", "hanzpo.com")).toBe("https://a.b.hanzpo.com/x?y=1");
  });

  it("rejects other hosts, http, and lookalikes", () => {
    for (const bad of [
      "https://evil.com",
      "http://foo.hanzpo.com",
      "https://hanzpo.com.evil.com",
      "https://evilhanzpo.com",
      "https://user@evil.com",
      "https://x@foo.hanzpo.com",
      "javascript:alert(1)",
      "//evil.com",
      "not a url",
    ]) {
      expect(safeReturn(bad, "hanzpo.com"), bad).toBeNull();
    }
  });
});

describe("login flow", () => {
  it("sends the user to Google with state and nonce", async () => {
    const res = await call("/login?return=https://foo.hanzpo.com/");
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin).toBe("https://accounts.google.com");
    expect(loc.searchParams.get("redirect_uri")).toBe("https://auth.hanzpo.com/callback");
    expect(loc.searchParams.get("state")).toBeTruthy();
    expect(loc.searchParams.get("nonce")).toBeTruthy();
    expect(cookieValue(res, "auth_state")).toBeTruthy();
  });

  it("sets a hanzpo.com-wide cookie and returns to the app", async () => {
    const res = await signIn();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://foo.hanzpo.com/page?x=1");
    const session = res.headers.getSetCookie().find((c) => c.startsWith("hanzpo_auth="))!;
    expect(session).toContain("Domain=hanzpo.com");
    expect(session).toContain("HttpOnly");
  });

  it("lets an app on another subdomain read the user", async () => {
    const token = cookieValue(await signIn(), "hanzpo_auth");
    const user = await getUser(new Request("https://foo.hanzpo.com/", { headers: { cookie: `hanzpo_auth=${token}` } }));
    expect(user).toEqual({ sub: "g-1", email: "me@example.com", name: "Me", picture: undefined });
  });

  it("skips Google when already signed in", async () => {
    const token = cookieValue(await signIn(), "hanzpo_auth");
    const res = await call("/login?return=https://bar.hanzpo.com/", { cookie: `hanzpo_auth=${token}` });
    expect(res.headers.get("location")).toBe("https://bar.hanzpo.com/");
  });

  it("ignores a return URL outside hanzpo.com", async () => {
    const res = await signIn({}, "https://evil.com/");
    expect(res.headers.get("location")).toBe("https://auth.hanzpo.com/");
  });

  it("rejects a mismatched state", async () => {
    const login = await call("/login");
    const res = await call("/callback?code=abc&state=wrong", { cookie: `auth_state=${cookieValue(login, "auth_state")}` });
    expect(res.status).toBe(400);
  });

  it("rejects a missing state cookie", async () => {
    expect((await call("/callback?code=abc&state=x")).status).toBe(400);
  });

  for (const [what, claims] of [
    ["wrong audience", { aud: "other" }],
    ["wrong nonce", { nonce: "nope" }],
    ["unverified email", { email_verified: false }],
    ["expired token", { exp: 1 }],
    ["wrong issuer", { iss: "https://evil.com" }],
  ] as const) {
    it(`rejects ${what}`, async () => {
      const res = await signIn(claims);
      expect(res.status).toBe(400);
      expect(cookieValue(res, "hanzpo_auth")).toBeUndefined();
    });
  }

  it("logs out across subdomains", async () => {
    const res = await call("/logout?return=https://foo.hanzpo.com/");
    expect(res.headers.get("location")).toBe("https://foo.hanzpo.com/");
    const c = res.headers.getSetCookie().find((c) => c.startsWith("hanzpo_auth="))!;
    expect(c).toContain("Max-Age=0");
    expect(c).toContain("Domain=hanzpo.com");
  });
});

describe("/me", () => {
  it("returns the user with CORS for hanzpo.com origins only", async () => {
    const token = cookieValue(await signIn(), "hanzpo_auth");
    const ok = await call("/me", { cookie: `hanzpo_auth=${token}`, origin: "https://foo.hanzpo.com" });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://foo.hanzpo.com");
    expect(((await ok.json()) as { email: string }).email).toBe("me@example.com");

    const other = await call("/me", { cookie: `hanzpo_auth=${token}`, origin: "https://evil.com" });
    expect(other.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("401s without a session", async () => {
    expect((await call("/me")).status).toBe(401);
  });
});

describe("client helper", () => {
  it("rejects a tampered token", async () => {
    const token = cookieValue(await signIn(), "hanzpo_auth")!;
    const [h, p, s] = token.split(".");
    const forged = `${h}.${b64json({ ...JSON.parse(atob(p!.replace(/-/g, "+").replace(/_/g, "/"))), email: "admin@example.com" })}.${s}`;
    expect(await getUser(new Request("https://foo.hanzpo.com/", { headers: { cookie: `hanzpo_auth=${forged}` } }))).toBeNull();
  });

  it("redirects page loads to login and 401s API calls", async () => {
    const page = await requireUser(new Request("https://foo.hanzpo.com/x", { headers: { accept: "text/html" } }));
    expect((page as Response).headers.get("location")).toBe(
      "https://auth.hanzpo.com/login?return=https%3A%2F%2Ffoo.hanzpo.com%2Fx",
    );
    expect(((await requireUser(new Request("https://foo.hanzpo.com/api"))) as Response).status).toBe(401);
  });

  it("enforces an allowlist", async () => {
    const token = cookieValue(await signIn(), "hanzpo_auth");
    const req = new Request("https://foo.hanzpo.com/", { headers: { cookie: `hanzpo_auth=${token}` } });
    expect(((await requireUser(req, { allow: ["someone@else.com"] })) as Response).status).toBe(403);
    expect(await requireUser(req, { allow: ["ME@example.com"] })).toMatchObject({ email: "me@example.com" });
  });

  it("uses devEmail only on localhost", async () => {
    expect(await getUser(new Request("http://localhost:5173/"), { devEmail: "dev@x.com" })).toMatchObject({ email: "dev@x.com" });
    expect(await getUser(new Request("https://foo.hanzpo.com/"), { devEmail: "dev@x.com" })).toBeNull();
  });
});
