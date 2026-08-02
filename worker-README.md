# Crowd-sourced signature backend (D2)

This is **not loaded by the extension's own code bundle** — it's a separate
Cloudflare Worker, deployed independently, that the extension talks to over
plain HTTPS. As of v9.5.2, the extension ships with **"Crowd-sourced
signatures" ON by default**, pre-pointed at the maintainer's own deployed
instance of this Worker:

```
https://cdnwaf-crowd-signatures.minhvutanlaphanoi.workers.dev/report
```

You can turn this off, or repoint it at your own deployment, any time in
the extension's Settings page — the toggle and endpoint field are exactly
where they always were.

## What it does

Collects small notes like *"saw header X-Foo-Edge on Cloudflare that isn't
tracked yet"*, grouped by provider — plus, as of v9.5.9, the domain the
header was seen on. Domain is included deliberately: it lets a reviewer
tell a header that's corroborated across many unrelated domains (real
provider signal) from one that only ever shows up on a single domain
(almost certainly that domain's own application header, not this
provider's). No IP address is ever sent, and nothing beyond the domain
itself (see `maybeSubmitCrowdReport()` in `background.js`). This is no
longer an anonymous-data feature — it's on by default, and the person can
turn it off in Settings if they'd rather not share the domain.

## Deploy your own copy instead (optional)

You need a free Cloudflare account and `wrangler` (Cloudflare's CLI).

```bash
npm install -g wrangler
wrangler login

# Create the KV namespace that stores reports
wrangler kv namespace create REPORTS
# ^ copy the returned "id" into wrangler.toml below

wrangler deploy
```

### `wrangler.toml` (create this next to `crowd-signatures-worker.js`)

```toml
name = "cdnwaf-crowd-signatures"
main = "crowd-signatures-worker.js"
compatibility_date = "2026-01-01"

kv_namespaces = [
  { binding = "REPORTS", id = "PASTE_YOUR_KV_NAMESPACE_ID_HERE" }
]
```

After `wrangler deploy`, you'll get a URL like
`https://cdnwaf-crowd-signatures.<your-subdomain>.workers.dev`.
**Important**: the endpoint field in Settings must include the `/report`
path — the extension POSTs directly to whatever string is configured
there, with no path appended, and the Worker only accepts `POST` on
`/report` (a request to `/` with no path is handled separately, as the
dashboard — see below).

## Wire it up in the extension

1. Open the extension popup → **⚙ Settings**.
2. **Enable reporting** is on by default. Leave it on to contribute to the
   shared instance above, or paste your own `https://your-worker-url/report`
   into the endpoint field to use your own deployment instead.

## Reviewing submitted reports

`GET https://your-worker-url/` (or `/dashboard`) renders a built-in HTML
dashboard with per-provider report counts and the most common notes.
`GET https://your-worker-url/reports?provider=cloudflare` returns the raw
JSON list for a single provider. Neither endpoint has **any authentication**
in the code as shipped — add your own (a shared secret header, Cloudflare
Access, etc.) before relying on either for anything beyond casual personal
use, especially if you deploy your own copy and don't want the dashboard
world-readable.

## Limits baked into the Worker

- Max 5 note strings per report, 300 chars each (truncated, not rejected).
- Max 500 stored reports per provider (oldest dropped first).
