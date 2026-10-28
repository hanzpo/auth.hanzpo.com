import type { User } from "../client/hanzpo-auth";

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const shell = (body: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in</title>
<style>
  :root { --bg: #fff; --fg: #111; --muted: #666; --line: #ddd; --btn: #111; --btn-fg: #fff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #111; --fg: #eee; --muted: #999; --line: #333; --btn: #eee; --btn-fg: #111; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
    background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, -apple-system, sans-serif; }
  main { width: 100%; max-width: 320px; text-align: center; }
  img { width: 64px; height: 64px; border-radius: 50%; }
  h1 { font-size: 20px; font-weight: 600; margin: 12px 0 4px; }
  p { margin: 0 0 24px; color: var(--muted); overflow-wrap: anywhere; }
  .btn { display: block; width: 100%; padding: 12px; border: 0; border-radius: 10px; text-decoration: none;
    font: inherit; font-weight: 500; cursor: pointer; background: var(--btn); color: var(--btn-fg); }
  .btn.plain { background: none; color: var(--fg); border: 1px solid var(--line); }
</style>
</head>
<body><main>${body}</main></body>
</html>`;

const html = (body: string, status = 200) =>
  new Response(shell(body), { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });

export const signedIn = (u: User) =>
  html(`${u.picture ? `<img src="${esc(u.picture)}" alt="" referrerpolicy="no-referrer">` : ""}
<h1>${esc(u.name ?? u.email)}</h1>
<p>${esc(u.email)}</p>
<a class="btn plain" href="/logout">Sign out</a>`);

export const signedOut = () =>
  html(`<h1>Not signed in</h1>
<p>hanzpo.com</p>
<a class="btn" href="/login">Sign in with Google</a>`);

export const handoff = (action: string, token: string, back: string) =>
  html(`<form method="post" action="${esc(action)}">
<input type="hidden" name="token" value="${esc(token)}">
<input type="hidden" name="return" value="${esc(back)}">
<h1>Signing you in</h1>
<p>${esc(new URL(action).hostname)}</p>
<button class="btn" type="submit">Continue</button>
</form>
<script>document.forms[0].submit()</script>`);

export const failed =(message: string) =>
  html(`<h1>Couldn't sign in</h1>
<p>${esc(message)}</p>
<a class="btn" href="/login">Try again</a>`, 400);
