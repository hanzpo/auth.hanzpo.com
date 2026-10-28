# auth.hanzpo.com

One Google sign-in for every app on `*.hanzpo.com`. You sign in once at auth.hanzpo.com. Each app then gets its own ES256 token, valid only for that app's hostname and stored in a cookie only that app receives. Apps check it against the public key at `/.well-known/jwks.json`, so they need no Google client and no secrets, and one app's cookie is useless on another.

## Using it in an app

Copy `client/hanzpo-auth.ts` into the app. It has no dependencies.

```ts
import { handleAuth, requireUser } from "./hanzpo-auth";

export default {
  async fetch(req: Request, env: Env) {
    const auth = await handleAuth(req);
    if (auth) return auth;
    const user = await requireUser(req, { allow: ["hanznathanpo@gmail.com"], devEmail: env.DEV_EMAIL });
    if (user instanceof Response) return user;
    return new Response(`Hi ${user.email}`);
  },
};
```

- `handleAuth` serves `POST /.auth/callback` (sign-in lands here) and `/.auth/logout`. Those paths must reach the Worker, so add them to `run_worker_first` if the app serves static assets first.
- `requireUser` redirects page loads to sign-in, returns 401 for other requests, and returns 403 when the email isn't in `allow`. Leave out `allow` to let any Google account in.
- `getUser` returns the user or `null`.
- The cookie can't reach `localhost`, so set `DEV_EMAIL` in `.dev.vars` to act as that user during local dev. It only applies on `localhost` and `127.0.0.1`.
- Sign-in link: `https://auth.hanzpo.com/login?return=<url>`. Add `&switch=1` to choose another Google account.
- Sign-out link: `/.auth/logout` on the app. It clears the app's cookie and the auth.hanzpo.com session. Other apps stay signed in until their token expires (7 days).

`return` must be an https URL on `hanzpo.com` or one of its subdomains.

## Endpoints

| Path | |
| --- | --- |
| `/` | Shows who is signed in |
| `/login?return=` | Sends you to Google if needed, then posts an app token to `<app>/.auth/callback` |
| `/callback` | Google redirect URI |
| `/logout?return=` | Ends the auth.hanzpo.com session |
| `/me` | Signed-in user as JSON, with CORS for `*.hanzpo.com` |
| `/.well-known/jwks.json` | Public signing key |

## Setup

Secrets: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SIGNING_KEY` (from `npm run keygen`).

The Google OAuth client needs `https://auth.hanzpo.com/callback` as an authorized redirect URI.

Rotating `SIGNING_KEY` signs everyone out. Apps pick up the new key within a minute.

```sh
npm run check
npm run deploy
```
