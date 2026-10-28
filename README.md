# auth.hanzpo.com

One Google sign-in for every app on `*.hanzpo.com`. It signs a session token with ES256 and stores it in a cookie on `.hanzpo.com`. Apps check that token against the public key at `/.well-known/jwks.json`, so they need no Google client and no secrets.

## Using it in an app

Copy `client/hanzpo-auth.ts` into the app. It has no dependencies.

```ts
import { requireUser, getUser, logoutUrl } from "./hanzpo-auth";

export default {
  async fetch(req: Request, env: Env) {
    const user = await requireUser(req, { allow: ["hanznathanpo@gmail.com"], devEmail: env.DEV_EMAIL });
    if (user instanceof Response) return user;
    return new Response(`Hi ${user.email}`);
  },
};
```

- `requireUser` redirects page loads to sign-in, returns 401 for other requests, and returns 403 when the email isn't in `allow`. Leave out `allow` to let any Google account in.
- `getUser` returns the user or `null`.
- The cookie can't reach `localhost`, so set `DEV_EMAIL` in `.dev.vars` to act as that user during local dev. It only applies on `localhost` and `127.0.0.1`.
- From the browser, `fetch("https://auth.hanzpo.com/me", { credentials: "include" })` returns the user or 401.
- Sign-in link: `https://auth.hanzpo.com/login?return=<url>`. Add `&switch=1` to choose another Google account.
- Sign-out link: `https://auth.hanzpo.com/logout?return=<url>`.

`return` must be an https URL on `hanzpo.com` or one of its subdomains.

## Endpoints

| Path | |
| --- | --- |
| `/` | Shows who is signed in |
| `/login?return=` | Sends you to Google, or straight back if you're already signed in |
| `/callback` | Google redirect URI |
| `/logout?return=` | Clears the cookie everywhere |
| `/me` | Current user as JSON, with CORS for `*.hanzpo.com` |
| `/.well-known/jwks.json` | Public signing key |

## Setup

Secrets: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SIGNING_KEY` (from `npm run keygen`).

The Google OAuth client needs `https://auth.hanzpo.com/callback` as an authorized redirect URI.

Rotating `SIGNING_KEY` signs everyone out. Apps pick up the new key within a minute.

```sh
npm run check
npm run deploy
```
