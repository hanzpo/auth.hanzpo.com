import { AUTH_ORIGIN, COOKIE, b64urlEncode, decodeJson, readCookie, verifyToken, type User } from "../client/hanzpo-auth";
import { failed, signedIn, signedOut } from "./page";

export interface Env {
  DOMAIN: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SIGNING_KEY: string;
}

const STATE = "auth_state";
const MAX_AGE = 60 * 60 * 24 * 30;
const enc = new TextEncoder();
const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;

interface SigningKey {
  kid: string;
  priv: CryptoKey;
  pub: CryptoKey;
  jwk: JsonWebKey & { kid: string; alg: string; use: string };
}

let cached: { raw: string; key: Promise<SigningKey> } | undefined;

function signingKey(env: Env): Promise<SigningKey> {
  if (cached?.raw !== env.SIGNING_KEY) {
    const load = async (): Promise<SigningKey> => {
      const { kty, crv, x, y, d, kid } = JSON.parse(env.SIGNING_KEY) as JsonWebKey & { kid: string };
      const jwk = { kty: kty!, crv: crv!, x: x!, y: y!, kid, alg: "ES256", use: "sig" };
      return {
        kid,
        priv: await crypto.subtle.importKey("jwk", { kty, crv, x, y, d }, ALG, false, ["sign"]),
        pub: await crypto.subtle.importKey("jwk", { kty, crv, x, y }, ALG, false, ["verify"]),
        jwk,
      };
    };
    cached = { raw: env.SIGNING_KEY, key: load() };
  }
  return cached.key;
}

const b64json = (o: unknown) => b64urlEncode(enc.encode(JSON.stringify(o)));

async function signToken(user: User, key: SigningKey, now: number): Promise<string> {
  const data = `${b64json({ alg: "ES256", typ: "JWT", kid: key.kid })}.${b64json({ ...user, iss: AUTH_ORIGIN, iat: now, exp: now + MAX_AGE })}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.priv, enc.encode(data));
  return `${data}.${b64urlEncode(new Uint8Array(sig))}`;
}

export function safeReturn(raw: string | null, domain: string): string | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password) return null;
  return u.hostname === domain || u.hostname.endsWith(`.${domain}`) ? u.toString() : null;
}

function cookie(name: string, value: string, maxAge: number, domain?: string) {
  return [`${name}=${value}`, domain && `Domain=${domain}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax", `Max-Age=${maxAge}`]
    .filter(Boolean)
    .join("; ");
}

function redirect(location: string, cookies: string[] = []) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 302, headers });
}

async function sessionUser(req: Request, key: SigningKey): Promise<User | null> {
  const token = readCookie(req.headers.get("cookie"), COOKIE);
  return token ? verifyToken(token, async (kid) => (kid === key.kid ? key.pub : undefined)) : null;
}

const random = () => b64urlEncode(crypto.getRandomValues(new Uint8Array(24)));

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const key = await signingKey(env);
    const domain = url.hostname === env.DOMAIN || url.hostname.endsWith(`.${env.DOMAIN}`) ? env.DOMAIN : undefined;
    const back = safeReturn(url.searchParams.get("return"), env.DOMAIN) ?? `${url.origin}/`;

    switch (url.pathname) {
      case "/": {
        const user = await sessionUser(req, key);
        return user ? signedIn(user) : signedOut();
      }

      case "/login": {
        if (!url.searchParams.has("switch") && (await sessionUser(req, key))) return redirect(back);
        const state = random();
        const nonce = random();
        const params = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: `${url.origin}/callback`,
          response_type: "code",
          scope: "openid email profile",
          state,
          nonce,
        });
        if (url.searchParams.has("switch")) params.set("prompt", "select_account");
        return redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, [
          cookie(STATE, b64json({ state, nonce, back }), 600),
        ]);
      }

      case "/callback": {
        const saved = readCookie(req.headers.get("cookie"), STATE);
        const code = url.searchParams.get("code");
        let pending: { state: string; nonce: string; back: string };
        try {
          pending = decodeJson(saved ?? "");
        } catch {
          return failed("The sign-in link expired. Start again.");
        }
        if (!code || url.searchParams.get("state") !== pending.state) return failed("The sign-in link expired. Start again.");

        const res = await fetch("https://oauth2.googleapis.com/token", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            code,
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${url.origin}/callback`,
            grant_type: "authorization_code",
          }),
        });
        if (!res.ok) return failed("Google didn't accept the sign-in.");
        const { id_token } = (await res.json()) as { id_token?: string };
        const c = id_token ? decodeJson(id_token.split(".")[1] ?? "") : {};
        const now = Math.floor(Date.now() / 1000);
        const valid =
          c.aud === env.GOOGLE_CLIENT_ID &&
          (c.iss === "https://accounts.google.com" || c.iss === "accounts.google.com") &&
          c.nonce === pending.nonce &&
          typeof c.exp === "number" && c.exp > now &&
          c.email_verified === true &&
          typeof c.sub === "string" &&
          typeof c.email === "string";
        if (!valid) return failed("Google returned an account that couldn't be verified.");

        const user: User = {
          sub: c.sub as string,
          email: c.email as string,
          ...(typeof c.name === "string" && { name: c.name }),
          ...(typeof c.picture === "string" && { picture: c.picture }),
        };
        return redirect(safeReturn(pending.back, env.DOMAIN) ?? `${url.origin}/`, [
          cookie(STATE, "", 0),
          cookie(COOKIE, await signToken(user, key, now), MAX_AGE, domain),
        ]);
      }

      case "/logout":
        return redirect(back, [cookie(COOKIE, "", 0, domain)]);

      case "/me": {
        const origin = req.headers.get("origin");
        const headers: Record<string, string> = { "content-type": "application/json", "cache-control": "no-store", vary: "origin" };
        if (origin && safeReturn(origin, env.DOMAIN)) {
          headers["access-control-allow-origin"] = origin;
          headers["access-control-allow-credentials"] = "true";
        }
        const user = await sessionUser(req, key);
        return new Response(JSON.stringify(user), { status: user ? 200 : 401, headers });
      }

      case "/.well-known/jwks.json":
        return new Response(JSON.stringify({ keys: [key.jwk] }), {
          headers: { "content-type": "application/json", "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" },
        });

      default:
        return new Response("Not found", { status: 404 });
    }
  },
};
