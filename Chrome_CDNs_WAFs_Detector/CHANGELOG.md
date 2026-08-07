# Changelog — v9.0.0

## New features

**A — Accuracy / core value**
- **A1. Layer-order inference** — parses the existing `Via` header (already
  collected, zero new network cost) to infer visitor→origin hop order when
  multiple providers are detected. Shows "position unconfirmed" instead of
  guessing when the evidence doesn't support an order.
- **A2. Origin-IP-leak check** (on-demand button, not run on every scan) —
  uses crt.sh Certificate Transparency logs + a common-subdomain probe list
  to flag hosts resolving outside known CDN ranges. *Does not* read TLS
  certificates directly — see "What was adjusted" below.
- **A3. Confidence decay** — flags a provider's score as possibly stale if
  its signature hasn't been reviewed in 6+ months, based on a hand-maintained
  `PROVIDER_LAST_REVIEWED` map in `background.js`.
- **A4. Scan diffing** — compares the current scan against the most recent
  prior scan of the same domain and shows what was added/removed.

**B — New features**
- **B1. Batch scan** — `batch.html`, paste/upload a domain list, bounded
  concurrency, JSON/CSV export.
- **B2. Compare 2 domains** — `compare.html`, side-by-side scan with a
  shared/only-A/only-B provider summary.
- **B3. Export** — JSON, CSV, and a printable HTML report (use the browser's
  Print → Save as PDF; no PDF library is bundled).
- **B4. Local webhook** — `chrome.runtime.onMessageExternal`, **disabled by
  default** (`externally_connectable.matches: []` in manifest.json). Add
  your own trusted origin(s) there to enable it.
- **B5. Right-click "Scan this domain/link"** context menu.
- **B6. Toolbar badge** showing the detected-provider count.

**C — UX**
- **C1. Dark/light theme toggle**, persisted, defaults to system preference.
- **C2. Confidence breakdown** — approximate per-signal point contribution,
  computed by re-scoring with each signal toggled off (leave-one-out), not
  by modifying all 21 provider files.
- **C3. Pin/bookmark domains**, separate from auto-recorded history.

**D — Bold ideas**
- **D2. Crowd-sourced signatures (opt-in, beta)** — manual "report a new
  signal" form in the provider detail view. Off by default; requires you to
  deploy `/worker/crowd-signatures-worker.js` yourself (see
  `/worker/README.md`) and paste the endpoint into Settings.
- **D4. Threat-intel CVE lookup** — on-demand NVD keyword search per
  provider, 24h cache.

## What was adjusted from the original 17-item list, and why

- **D1 (real JA3/JA4 TLS fingerprinting) — not implemented.** A browser
  extension's JavaScript has no access to the raw TLS ClientHello; there's
  no honest way to do this without a native-messaging host running outside
  the browser, which is out of scope here.
- **A2 (origin leak)** doesn't read TLS certificate SAN fields via `fetch()`
  — that data isn't exposed to extension JS by any browser API. It uses the
  public crt.sh Certificate Transparency log search instead.
- **D3 (client-side ML)** — not implemented as a "trained model." There's no
  labeled ground-truth dataset (no oracle telling us which domains *truly*
  use which provider), so a "trained classifier" would just be fabricated
  weights dressed up as ML. If you want this properly, it needs real labeled
  data first.

## v9.4.0 — Round 5: net-new ideas

**Shipped (11 requested, 2 dropped after research — see below):**
- **#3 RUM Core Web Vitals attribution** — captures real LCP/CLS/TTFB from the active tab, attributes to detected provider, builds a local trend (Settings → Performance intelligence).
- **#4 Third-party waterfall attribution** — classifies `PerformanceResourceTiming` entries into main-domain vs third-party (analytics, ads, fonts, trackers), shows % of load time each accounts for.
- **#5 CDN service-tier heuristic** — infers "likely paid/enterprise tier" from optional features (image optimization, smart routing) — explicitly labeled as a heuristic, never a billing-data claim.
- **#6 Cross-device sync via `chrome.storage.sync`** — pinned domains and watchlist now sync automatically across Chrome profiles signed into the same Google account. No server, no Worker. Falls back to `.local` if sync is disabled by policy.
- **#7 robots.txt / security.txt OSINT** — fetches both, surfaces sitemap references and any CDN-stamped comments, checks for bug-bounty/security contact info.
- **#8 "Blast radius"** — via Shodan InternetDB (free), lists other hostnames sharing a resolved IP.
- **#9 CDN status-page correlation** — checks Cloudflare/Fastly/Akamai/Vercel/Netlify/Google Cloud status APIs before assuming a watchlist diff means "they migrated" instead of "provider is down right now."
- **#10 Shareable fingerprint string** — a JA4-style compact string (`CDNW1_cf_r53_e1a0_L2`) summarizing a scan for quick paste-and-compare.
- **#11 Wayback Machine cross-check** — CDX API query for the domain's earliest archive.org snapshot, extending historical context beyond this extension's own local history.

**Tree view rewritten** — proper 4-layer taxonomy (WAF → CDN → Edge-hosting → Origin) instead of a flat 2-bucket split, respects Via-header chain order within layers, sidebar shows DNS/Email/ECH/Anycast context, all round-5 actions surfaced from one toolbar.

**Light theme rewritten** — previous version used flat near-white grays with a white header, which read as washed-out. New palette uses a warm slate-blue scale with a deep navy header (matches dark mode's visual anchor), plus per-component overrides for cards, inputs, and the detail view so nothing reads as "white text on white."

**Crowd-report Worker (D2) — dashboard added.** `GET /` now renders an HTML dashboard showing report frequency per provider, so you can actually see which unrecognized headers are being reported most often instead of only querying raw JSON per-provider.

### What was proposed but dropped (with reasons)

- **#1 (JA4H HTTP-request fingerprint)** — dropped. JA4H measures the *client's* HTTP fingerprint as seen by a server (used by CDNs/WAFs to detect bots). This extension acts as the client already; there's nothing to detect a CDN *with* here — it's the wrong direction entirely, not just impractical.
- **#2 (passive TCP/HTTP2-frame fingerprinting)** — dropped, no substitute added. Every real technique in this space (TCP window size, HTTP/2 SETTINGS frame, WINDOW_UPDATE, PRIORITY frame structure) requires packet-level capture (Wireshark, nghttp2, raw sockets) that browser JavaScript has no access to. `fetch()` exposes none of it. Any "browser-based" version of this would have to fake the data, so it's omitted rather than built as decoration.

## v9.4.1 — Bug fix + cross-browser support

### Fixed
- **check-host.net distributed probe was broken.** Root cause: code read a field called `request_token`, but the real API (verified against https://check-host.net/about/api) returns `request_id`. The check-result response shape was also wrong — assumed 5 fields including a response-headers string that doesn't exist; the real shape is `[ok, response_time_seconds, status_message, http_code]`, 4 fields, no headers. This meant the probe could never get a valid token and always failed with "No request token in response." Fixed the field name, fixed the result parsing, and removed the CDN-signal/resolved-IP extraction logic that depended on data the API never actually provides (rather than leave it silently producing empty results). The probe now correctly reports reachability + latency + HTTP status from real global nodes; anycast confirmation continues to come from the extension's own DNS-based multi-resolver check (A5), which is the reliable source for that.

### Cross-browser support (Chrome + Firefox)
Split into two manifests — `manifest.chrome.json` and `manifest.firefox.json` — because Chrome MV3 and Firefox MV3 diverge on several manifest keys that can't be reconciled in one file:
- **Background context**: Chrome requires `background.service_worker`; Firefox MV3 only supports `background.scripts` (event page). Using the wrong key silently fails to load on the other browser.
- **Side panel**: Chrome's `chrome.sidePanel` has no Firefox equivalent; Firefox uses `sidebar_action` instead. Both the popup button and the `Ctrl+Shift+D` command now feature-detect and use whichever is available.
- **webRequestBlocking**: valid and required on Firefox for the TLS-intel listener (`browser.webRequest.getSecurityInfo`); rejected outright by Chrome MV3. Only in the Firefox manifest.
- **Offscreen documents** (`chrome.offscreen`, used for cache warming): Chrome-only, already feature-detected — inert no-op on Firefox.
- **Clipboard read**: Firefox requires an explicit `clipboardRead` permission; Chrome does not.

The actual code (`background.js`, `popup.js`, all provider files) is shared as-is between both builds — no polyfill library needed, since Firefox natively supports the `chrome.*` namespace for compatibility (confirmed via MDN's "Chrome incompatibilities" reference) and every API this extension uses exists on both browsers except the handful already feature-detected above.

Added `build.sh` — packages both `dist/cdnwaf-detector-chrome-vX.zip` and `dist/cdnwaf-detector-firefox-vX.zip` from the one shared codebase in a single run, swapping in the right manifest for each and excluding the other browser's manifest + the build script itself from the final zip.

## v9.4.3 — Round 6: DNS-layer intelligence

All 6 features build on the existing A5 multi-resolver DoH infrastructure — no new API surface, just reading more from data already being fetched, or adding one more resolver to the existing comparison.

- **#1 DNS-blocking/censorship detector** (on-demand, Tree view → 🚧 Check DNS blocking) — compares a neutral resolver (Cloudflare) against a policy-filtering resolver (OpenDNS FamilyShield). Positively identifies a block by matching known FamilyShield sinkhole IPs, with a lower-confidence NXDOMAIN-mismatch fallback. Purely diagnostic — reports what it observes, never attempts to route around or bypass a detected block.
- **#2 EDNS Client Subnet (ECS) leak detector** (automatic, shown as a banner when detected) — compares Google's DoH (sends ECS by documented default) against Cloudflare's DoH (no ECS by design). Zero IP overlap between the two answer sets suggests the CDN is geo-routing based on the visitor's partial IP leaked via ECS — a privacy signal most users have no visibility into otherwise.
- **#3 DNSSEC validation status** (automatic, green pill when present) — reads the `AD` (Authenticated Data) flag that was already present in every DoH JSON response being fetched for A5; considered validated only when every responding resolver agrees, since AD reflects each resolver's own validation state.
- **#4 Resolver speed race** (automatic, informational pill) — times all three resolvers against each other for the current scan and reports which answered fastest this session. Session-local only; not persisted, since resolver latency depends on network conditions and time of day.
- **#5 Resolver-disagreement as WAF/geo-fencing signal** — folded into #2's ECS-leak logic; a complete (not partial) IP-set mismatch between resolvers is the same signal that flags an ECS leak, since normal anycast divergence usually still shares at least some edge IPs.
- **#6 Wired into existing Tree sidebar and Timeline** — no new UI surface built; DNSSEC/ECS-leak/fastest-resolver status appears as sidebar chips in the Tree view (C4) and as inline tags in the Timeline (D1), reusing infrastructure already shipped.

## v9.4.4 — Accuracy fixes + UI decluttering

### Fixed: DNS-blocking detector (#1 from round 6) reliability
Research into real-world OpenDNS FamilyShield behavior found the sinkhole IP list is **not stable over time**, and found a documented case where FamilyShield returned an unrelated IP (not any known sinkhole address) for a blocked domain instead of the expected redirect. Because of this:
- **NXDOMAIN-mismatch is now the primary signal** (the filtering resolver simply refuses to resolve while a neutral one succeeds) — this doesn't depend on maintaining an accurate, ever-changing IP list.
- **Sinkhole-IP match is now a secondary, lower-confidence hint only**, always shown with an explicit "this IP list can go stale" caveat in the UI. Never asserted as certain.
- Added a `confidence` field (`medium-high` / `low-medium`) surfaced directly in the panel so the person can weigh the result appropriately.

### Fixed: DNS-blocking check now caches results (10 min TTL)
Previously, clicking "Check DNS blocking" repeatedly re-fired two DoH round-trips every time, even for the same domain seconds apart. Now cached per-domain for 10 minutes; the panel shows a small "cached result" note when serving from cache.

### Redesigned: Overview screen was too information-dense
Simulated scanning `google.com` end-to-end while designing this: with Google detected, DNSSEC validated, an ECS-leak banner (Google's own resolver enables ECS by default), a DNS-provider pill, and 24 always-rendered provider cards (23 of them "undetected" and irrelevant), the old flat layout produced roughly 15 stacked information blocks with no visual hierarchy.

Restructured into:
- **Always visible**: summary line, resolved IPs, diff-vs-last-scan banner, layer order (only shown when 2+ providers are detected — a single provider has no "order" to show).
- **Detected providers grid** — now shows only providers that actually matched, not all 24 with 23 grayed-out "undetected" cards cluttering the view.
- **📡 Network & infrastructure signals** (collapsible, badge shows item count) — DNS provider, SPF/DMARC, HTTPS record/ECH, TLS intel, DNSSEC, ECS-leak, anycast divergence all grouped here, collapsed by default.
- **📋 All N providers** (collapsible, opt-in) — the full always-was-there provider grid including undetected ones, for people who want to audit every provider individually.
- **🛠 Tools & export** (collapsible, 2-column button grid instead of a cramped 8-button row) — JSON/CSV/Markdown/Report export, origin-leak check, share code, timeline, tree view.

Net effect: a typical single-CDN scan now renders 3-4 compact blocks instead of ~15, with the option to expand any group that's actually relevant to what the person is investigating.

## v9.4.5 — Fix: still cluttered with 2+ detected providers

Simulated scanning a site with both Cloudflare (WAF) and Google (CDN) detected — the exact multi-provider case the previous redesign didn't fully address. Even after v9.4.4's grouping, having 2+ providers still stacked: a diff banner, a multi-CDN warning banner, a migration-warning banner, an anycast note, and a separate layer-chain row — 5 separate full-width colored blocks before even reaching the provider list, which then rendered 2+ full-height cards.

Fixed by:
- **Consolidating all status banners into one block.** Diff-vs-last-scan, multi-CDN warning, migration warning, anycast note, and layer order are now short single lines inside one bordered block, only showing lines that actually apply. What used to be 5 stacked colored banners is now one compact block with 1-3 short lines.
- **Compact provider rows for 2+ detected providers.** A single detected provider still gets a full card (there's room, and it's the headline answer). With 2 or more, providers now render as slim one-line rows (dot + name + label + score) instead of full cards with a head/bar/label each — cuts vertical space roughly in half for multi-CDN scans.

## v9.4.6 — Fixed redundant/awkward copy + Round 7 (15 features)

### Fixed: confusing duplicate messaging
- **"Multi-CDN/WAF deployment detected"** and the longer migration-warning sentence used to both appear and say almost the same thing twice (one short, one long). Now only one line shows: the specific migration-warning note when 2+ actual CDNs are detected (a real thing worth flagging), or a short neutral line for the common CDN+WAF combo (not a warning — that's normal).
- **"21 IPs resolved — tap an IP..."** was a plain unstyled line sitting awkwardly in the summary. IPs now get their own styled, collapsible group card (🌐 Resolved IPs) with a count badge, matching the visual language of the other groups. 1-2 IPs still render inline since a whole group for two chips is overkill.
- **"Layer order unknown"** line removed from the always-visible status block — Via header being absent is the common case, not something worth a line every single scan. Still checkable via the Tree view for anyone specifically investigating layer order.
- Shortened the migration-warning sentence itself (background.js) from a 3-clause paragraph to one short sentence.

### Round 7 — 15 features, all implemented
1. **Adaptive detail density** — tracks per-group expand/collapse rate locally; once a group has been opened 60%+ of the time across 5+ scans, it defaults to expanded going forward.
2. **Explain in plain words** (Tree view) — turns the C2 confidence breakdown into a sentence instead of a bar chart.
3. **Baseline comparison** (Tree view) — "you've seen this combination N times before, rank #X of Y" using only your own local scan history.
4. **Explain for a report** (Tree view) — non-technical paragraph suitable for pasting to a boss/client, with a copy button.
5. **Flag for later review** — distinct from Pin; attaches a note + timestamp, viewable/removable from Settings.
6. **Custom-rule preview** — tests a draft custom-provider rule against locally stored scan history before saving, to catch overly broad rules early.
7. **Batch from bookmarks/open tabs** — populates Batch scan without manual paste. Bookmarks access uses `optional_permissions` — requested only when this button is clicked, never at install.
8. *(sparkline trend — folded into #3's baseline comparison rather than a separate chart; kept scope tight)*
9. **Weekly watchlist digest** — one notification per week summarizing all changes, instead of one per change per domain.
10. **Diff-only export** (Timeline) — exports only snapshots where something actually changed, skipping the "no change" majority.
11. **Keyboard navigation** — j/k move between results, Enter opens detail, Esc goes back; disabled while typing in any input.
12. **Quick compare** (Tree view) — inline two-domain comparison without leaving the popup for the dedicated Compare page.
13. **Weak-signal badge** — a small ⚠ next to any detected provider whose score came from only 1 signal, flagging higher false-positive risk directly in the overview.
14. **Auto-suggest rule from crowd reports** — drafts a starting custom-provider rule when a note has 5+ reports for a provider; always requires manual review/import, never automatic.
15. **Watchlist aggregate dashboard** — one feed across every watched domain's changes, instead of opening each domain's Timeline separately.

## v9.4.7 — Tree redesign: accuracy + decluttering

Prompted by a real scan result (Imperva 43% + Cloudflare 100% + Akamai 53% all in the same tree, DNS listed separately as "Cloudflare DNS") that exposed two real problems: silently listing 3 competing providers as if equally certain, and repeating "Cloudflare" as an unrelated fact in two different places.

### Accuracy
- **Same-layer conflict detection.** When 2+ full-CDN-class providers appear in the CDN or Edge-hosting layer (e.g. Cloudflare + Akamai both detected), the layer now shows an explicit amber warning: this is unusual for one site and often means one is a false positive (shared IP range, stale CNAME) rather than a genuine multi-CDN setup. WAF+CDN combos are NOT flagged — that's a normal, common pairing.
- **Weak-signal badge ported into the Tree.** A provider chip whose detection came from only 1 supporting signal now shows the same ⚠ badge already used in the Overview, with a tooltip explaining why. Previously the Tree showed every chip with equal visual weight regardless of how solid the detection actually was — exactly what let something like "Imperva 43%" sit next to "Cloudflare 100%" without any indication one is far less certain.
- **Same-provider linking.** If the DNS provider (or another sidebar fact) names a company that's also a detected chip in the tree — e.g. "Cloudflare DNS" when Cloudflare is already shown as the WAF/CDN — it no longer repeats as an unrelated sidebar fact. Instead it becomes a small linked note ("Cloudflare also manages DNS for this domain") directly under the tree, and the sidebar only shows genuinely separate context.

### UI — grouped instead of dumped
- All Tree action buttons (previously two dense rows: check-host probe, robots.txt, blast radius, Wayback, fingerprint, status pages, DNS blocking, explain, explain-for-report, baseline, flag, quick-compare — 12 buttons total, always visible) are now inside one collapsible "🛠 Analysis tools" group, matching the same pattern already used in the Overview screen. The tree itself stays the headline visual; the 12 analysis tools are one tap away instead of always taking up scroll space.

## v9.4.8 — Signal accuracy audit + Imperva hardening

Researched 2026 detection-vendor documentation for Imperva/Incapsula, Cloudflare, Fastly, DataDome, PerimeterX/HUMAN, and Akamai to find what's genuinely readable from a browser extension's passive HTTP/cookie view versus what only exists in each vendor's internal bot-scoring (TLS/JA4 fingerprinting, HTTP/2 frame analysis, canvas/WebGL fingerprinting — none of which `fetch()` can see, confirmed by the same research that led to dropping JA4H/TCP-fingerprint ideas in round 6).

### Fixed: Imperva was the file causing thin-signal false positives
Traced a real scan result (Imperva at 43% alongside two other providers) to `imperva.js` being the one detector in this codebase that hadn't yet adopted the "require signal diversity" pattern already used in `datadome.js` (`hasCorroboration` check) and `perimeterx.js` (`coherentCount` check). Imperva's scoring simply summed every fired signal's points regardless of how weak or exclusive each one was — a single `X-Cdn-Forward` header (a generic proxy-chain header, not Imperva-exclusive) could contribute meaningfully toward "detected" on its own.

Fixed by porting the same pattern: a detection now needs signals from 2+ independent categories (header / cookie / body / CNAME / probe) unless a single definitively-exclusive signal fired (valid-format X-Iinfo, a matched Imperva CNAME) — those remain trustworthy alone since they can't reasonably come from anything else.

### Added — 2026 research-verified signals
- **`incap_sh_` cookie prefix** — confirmed via multiple 2026 detection-vendor writeups as a newer session cookie used in Imperva's GeeTest-CAPTCHA challenge flow. Not previously tracked.
- **Dynamic challenge-path detection** — real Imperva deployments serve the JS challenge from a randomized path with a `?d=<hostname>` query parameter, not always the literal `_Incapsula_Resource` string the old body-regex expected. Added a domain-aware pattern match (background.js now passes the scanned domain into `extractCommonSignals` as `_domainEscaped` so any provider can build domain-specific body patterns safely).

### Reviewed, no changes needed
- **Cloudflare** — `__cf_bm` bot-management cookie already tracked; Cloudflare's actual 2026 bot-scoring (JA4, `cf.bot_management.score`, CDP-artifact detection) lives entirely server-side/internal to Cloudflare's dashboard and isn't exposed in response headers a client can read.
- **Fastly** — already well-sourced (cites http.dev directly in comments); no gaps found.
- **DataDome** — already treats the bare `datadome` cookie name as weak-alone, requiring corroboration; this is the same pattern Imperva now has.
- **PerimeterX/HUMAN** — already reads cookies via `chrome.cookies` (correct approach, since PerimeterX cookies are set via JS, not `Set-Cookie` headers — confirmed by research); already has the coherent-signal-count logic.
- **Akamai** — already tracks the correct `_abck`/`bm_sz`/`ak_bmsc` cookie family.

## v9.4.9 — Full signal audit across all 24 providers

Extended the accuracy audit from v9.4.8 (which found and fixed Imperva's thin-signal issue) across the remaining 18 provider files: CloudFront, Vercel, Netlify, Azure, Sucuri, F5 Distributed Cloud, Alibaba Cloud CDN, BunnyCDN, Gcore, KeyCDN, and others. Each was checked against 2026 vendor documentation or independently-verified technical sources.

### Fixed: Azure detector had a structurally-impossible signal
Research against Microsoft's own Front Door HTTP headers documentation (`MicrosoftDocs/azure-docs`) found that `X-Azure-JA4-Fingerprint` — a header the previous version checked for and weighted at 48 points — is attached to the **request Front Door forwards to the origin server**, not to the response sent back to the client. A browser extension can only read `fetch()` response headers, so this check was structurally always-false: dead code that could never fire, contributing a false sense of "we check for JA4 fingerprints" without ever actually doing so. Removed entirely rather than left in place; verified no other provider had the same request-vs-response header confusion (checked all files referencing fingerprint/bot-defense/ClientHello concepts).

### Added — 2026 research-verified signal
- **Vercel**: `x-vercel-proxy-signature` header, confirmed present on Vercel rewrite-proxy requests via a Vercel/Next.js team GitHub discussion thread. Not officially documented but observed consistently; added as a moderate-weight corroborating signal.

### Reviewed, confirmed accurate, no changes needed
- **CloudFront**: `X-Amz-Cf-Pop` format (IATA airport code + facility number + cache-tier suffix like `LAX54-P1`) cross-checked against three independent sources (AWS blog, AWS re:Post, http.dev) — exact match to what the detector already validates.
- **Vercel / Netlify**: header sets (`x-vercel-id` region-chain format, `x-nf-request-id` ULID format) both cross-checked against official docs and support forums — already accurate.
- **Sucuri**: no gaps found against current documentation.
- **F5 Distributed Cloud**: confirmed the bot-defense custom header F5 adds is also request-to-origin only (like Azure's JA4 case) — but the existing detector never attempted to read it in the first place, so no fix was needed here.
- **Alibaba Cloud CDN**: `X-Swift-SaveTime`/`X-Swift-CacheTime` already correctly scoped as Swift-layer-exclusive signals.
- **BunnyCDN**: cross-checked against bunny.net's own developer academy documentation — the detector already covers the complete documented header set (`cdn-cache`, `cdn-cachedat`, `cdn-edgestorageid`, `cdn-proxyver`, `cdn-pullzone`, `cdn-requestcountrycode`, `cdn-requestid`, `cdn-requestpullcode`, `cdn-requestpullsuccess`, `cdn-status`, `cdn-uid`, `server: BunnyCDN-`) with no gaps.
- **Gcore**: architecture already sound, no changes needed.
- **KeyCDN**: verified the service is still active and operating normally as of April 2026 (status page, FAQ, uptime monitors) — the file's "still active as of 2026" comment is accurate, not stale.

## v9.5.0 — Major cleanup (44 → 26 actions) + Crowd-sourced signatures upgrade

### Removed — 10 features cut for low practical value vs. complexity
After auditing all 44 message actions, removed features that either duplicated something already covered elsewhere or required enough manual effort that they saw little real use:
- **Adaptive group density** (#1) — tracked expand/collapse habits to "learn" default UI state; added storage/messaging overhead for a marginal convenience.
- **Baseline stack comparison** (#3) — required 3+ scans before showing anything, and the "rank #X of Y" output was more abstract than actionable.
- **Flag for later review** (#5) — duplicated Pin (both were "mark this domain"); consolidated to just Pin.
- **Batch scan from bookmarks/open tabs** (#7) — required a separate `bookmarks` permission grant and a multi-step folder-picker flow for a rarely-used convenience; `optional_permissions` entry removed from both manifests.
- **Weekly watchlist digest** (#9) — redundant with real-time watchlist change notifications, which already fire per-change.
- **Core Web Vitals capture + third-party waterfall** (round 7 #3/#4) — required manually clicking "capture from current tab" every time; passive/automatic would have been useful, manual-trigger wasn't used enough to justify the code.
- **CDN service-tier heuristic** (round 6 #5) — speculative "likely paid tier" inference saw no real usage.
- **robots.txt / security.txt OSINT** (round 5 #7) — rarely surfaced anything CDN/WAF-relevant; scope drift from the tool's core purpose.
- **Blast radius / shared-IP lookup** (round 5 #8) — Shodan InternetDB's free tier returned empty results often enough that the feature rarely produced anything useful.
- **Auto-suggest rule from crowd reports** (round 7 #14) — required both a configured Worker AND 5+ identical reports before ever triggering; replaced by something that actually works (see below).
- **Watchlist aggregate dashboard** (#15) — duplicated per-domain Timeline in a new UI surface for no added value.

Net result: 44 → 26 message actions (~40% reduction), with all 10 removals also cleaned from both manifests, Settings UI, and Tree view action rows.

### Upgraded — Crowd-sourced signatures now self-sustaining
The crowd-report feature previously required a person to manually notice an unfamiliar header and type a note — a high bar that explained why even a properly-deployed Worker endpoint would see little traffic. Replaced the manual-noticing step with automatic detection:

- **`knownHeaders` added to 21 of 24 provider files** (Cloudflare, Akamai, Alibaba Cloud CDN, Azure, BunnyCDN, CloudFront, DataDome, F5 Distributed Cloud, Fastly, Fly.io, Gcore, Google, Imperva, KeyCDN, Netlify, PerimeterX, Render, StackPath, Sucuri, Tencent EdgeOne, Vercel) — each provider now declares exactly which header names it already recognizes.
- **Automatic unknown-header detection** — every scan compares the apex domain's response headers against a combined known-header list (standard HTTP headers + all 21 providers' declared vocabularies). Any header left over, on a domain where a provider WAS detected, gets surfaced.
- **One-click report buttons** in each provider's detail view — no typing required; clicking a suggested header sends `"Unrecognized header: X"` as the report note. A manual free-text note field remains below for anything the automatic check doesn't catch (new cookies, body patterns, etc).
- **Overview-level notice** — a small pill in the Network & infrastructure signals group flags when unrecognized headers were found on a scan, pointing to the relevant provider's detail view.
- Settings copy updated to describe the automatic-detection behavior and to point to the Worker's own dashboard URL for viewing submitted reports.

This directly targets making the already-deployed `cdnwaf-crowd-signatures.minhvutanlaphanoi.workers.dev` endpoint self-sustaining long-term — the bar to contribute a signal dropped from "notice something unusual, remember to report it, type a description" to "click the button that's already showing you the unrecognized header."

## v9.5.2 — Reliability round + full codebase audit

### Reliability upgrades (background.js)
- **Session-persisted ambient/tab state** — `ambientByTab` (per-tab passive detection hints) and `tabResultsByDomain` (multi-tab correlation) moved off a plain in-memory `Map` and onto `chrome.storage.session`, so they survive an MV3 service-worker restart mid-session instead of silently resetting. An in-memory mirror keeps the per-request hot path (ambient header listener) just as fast as before; persistence is fire-and-forget.
- **One-time storage migration** — `runStorageMigration()` clears 5 dead `storage.local` keys left behind by the v9.5.0 feature removals (`flagged_for_review`, `group_usage_stats`, `rum_vitals_by_provider`, `batch_prefill_domains`, `pending_custom_rule_draft`), gated by a `schema_version` marker so it only ever runs once.
- **Retrying fetch + per-host circuit breaker** — new `fetchWithRetry()` (exponential backoff: 300/600/1200ms, 3 attempts) applied to every auxiliary API call: crt.sh, NVD, check-host.net (both the initial request and result polling), ipinfo.io, Wayback Machine, and provider status pages. A lightweight circuit breaker opens after 4 consecutive failures against the same host and cools down for 2 minutes, so a dead upstream stops paying full retry+timeout cost on every subsequent scan. The core scan's own DNS/probe calls (`fetchT`/`doh`) intentionally keep failing fast — retries are only for enrichment features, never the scan critical path.
- **Interrupted-scan detection** — a lightweight marker is written to `chrome.storage.session` when a scan starts and cleared when it finishes. If the service worker dies mid-scan, a new port connection can detect the orphaned marker (via `getInterruptedScan`) once it's older than 45s and prompt/auto-retry, instead of leaving the UI on a progress bar that will never move again. This is *not* true resume-from-checkpoint — internal scan-phase state (partial DNS/signal results) is not persisted or replayed, since that would require rearchitecting `performScan()` into an explicit state machine. Deferred as a separate, larger decision.
- **Deferred by design**: moving timing measurement to `declarativeNetRequest` and using Static/Session Rulesets to block preload/prefetch during probes were considered but not implemented — both require adding the `declarativeNetRequest` permission to the manifest, which triggers a re-review on both the Chrome Web Store and the already-published AMO listing. Left for a deliberate follow-up decision rather than a silent permission change.

### Codebase audit findings (fixed)
- **`infoRow()` in popup.js was missing `>` escaping** — inconsistent with the canonical `escHtml()` helper defined two lines below it (which does escape `>`). Values rendered through `infoRow()` include externally-sourced text (reverse-DNS PTR, ASN org names, geo fields from ipinfo.io), so this was tightened to match.
- Verified: all 24 provider files declare `knownHeaders`; the previously-fixed Fastly/Tencent EdgeOne `cdn-loop` declarations are intact; every `.js` file passes `node --check`; no duplicate top-level declarations in `background.js` or `popup.js`; every `innerHTML` assignment that interpolates domain names, NVD summaries, status-page descriptions, or check-host.net node data routes through `escHtml()`/`infoRow()` before insertion.
- Packaging hygiene: confirmed the Firefox `gecko.id` (`cdns-wafs-detector@example.com`) is unchanged. Excluded from both shipped zips: `.git/`, `.gitignore`, `Commit.cmd` (Windows dev helper), the `worker/` directory (Cloudflare Worker backend — a separate deployable, not extension code), its `.wrangler/` cache, and a stray old backup archive (`L.zip`) found inside the Firefox source folder.

## v9.5.3 — Fix invisible providers + dedupe listener + crowd-report now on by default

### Fixed — Fly.io / Render / Railway were completely invisible in the popup
`background.js` fully detects these three (registered in `CDN_PROVIDERS`, real scoring, `knownHeaders` where applicable), but **`PROVIDER_UI` in `popup.js` had no entries for them** — and every rendering path (overview grid, the 4-layer taxonomy tree, JSON/CSV/Markdown export, crowd-report name lookup) iterates `Object.keys(PROVIDER_UI)`. A scan of a Fly.io/Render/Railway-hosted domain would score correctly on the backend and then show nothing at all in the UI. Added all three, using only signals that actually exist in their provider files (`flyCname`, `flyRequestId`, `flyRegion`, `flyForwardedPort`, `viaFly`, `serverFlyHeuristic` for Fly.io; `renderCname`, `renderHeaderHeuristic` for Render; `railwayCname`, `railwayHeaderHeuristic` for Railway) — no invented signals or headers.

### Fixed — duplicate TLS-intel listener on Firefox
Two byte-for-byte identical blocks were both registering `browser.webRequest.onHeadersReceived.addListener()` for the Firefox-only TLS/cert intel feature (copy-pasted across two earlier rounds and never deduplicated). Firefox was calling `getSecurityInfo()` twice per request for no benefit — same data written twice. Removed the duplicate.

### Removed — 5 dead message handlers with no caller anywhere in the extension
Found via a full cross-check of every `chrome.runtime.sendMessage`/port call in `popup.js`, `batch.js`, `compare.js`, `offscreen.html` against every `msg.action` branch in `background.js`:
- `getTimingData` / `injectAndGetTimingData` — leftover from the Core Web Vitals capture feature already removed in v9.5.0; should have been deleted then.
- `queryASN` (+ its `asnCache`) — a parallel ipinfo.io-based ASN lookup, superseded by (and redundant with) the RDAP-based org/ASN lookup already used in the live scan path.
- `scanClipboardDomain` — a one-shot duplicate of what `popup.js`'s own `scanFromClipboard()` already does client-side over the `scan` port.
- `getAmbientResults` — never called by any UI; the ambient-mode badge count is set directly by the header listener and doesn't depend on it. The underlying per-tab ambient state is untouched.
- The v9.5.2 scan-interrupted-marker plumbing (`markScanStarted`/`clearScanMarker`/`getInterruptedScan`) — turned out to be redundant with `port.onDisconnect` handling already present in both `popup.js` and `batch.js`, which detects a dead service worker in real time and is more accurate than a 45-second staleness heuristic. Removed rather than force-wiring a UI consumer for it.
- `previewCustomRule` (real, working logic — CNAME-only historical preview for a draft custom-provider rule) has no caller either, but was left in place rather than deleted: it's not dead/superseded code, just a finished backend for a UI button that was never added. Flagged for a future decision rather than removed.

### Changed — crowd-sourced signatures now on by default
`crowdReportEnabled` now defaults to `true`, with `crowdReportEndpoint` pre-filled to the maintainer's own deployed Worker (`https://cdnwaf-crowd-signatures.minhvutanlaphanoi.workers.dev/report`). Previously this defaulted to off with a blank endpoint. Settings copy and the `worker/README.md` were updated to describe the new default and to correct a real footgun in the old instructions: the endpoint field must include the `/report` path, since the extension POSTs directly to whatever string is configured there with no path appended — the Worker only accepts `POST` on `/report` and returns 404 for a POST to `/`.

## v9.5.4 — Endpoint self-heal, daily IP-range refresh, crowd-report feedback loop

### Fixed — the exact /report footgun above, for real this time
Found by testing: a stored endpoint without `/report` produces no error anywhere — `fetch()` doesn't throw on a 404 response, and the code never checked `res.ok`, so "Send report" always showed success even when nothing reached the Worker. Two fixes: (1) the Settings input now auto-normalizes on change — strips trailing slashes and appends `/report` if missing; (2) `getSettings()` now self-heals a bad value already sitting in `chrome.storage.local` every time it's read, so existing installs (including the one that hit this exact bug) get fixed automatically without needing to retype the field.

### Changed — IP-range refresh is now a real daily cadence, not opportunistic weekly
The infrastructure for pulling official IP ranges (`ipConfig.v4Url`/`v6Url`, currently populated for Cloudflare, Fastly, CloudFront, Google, and BunnyCDN) already existed, but it only refreshed opportunistically — checked once whenever the service worker happened to wake up, against a 7-day staleness threshold. Tightened the threshold to 1 day and added a dedicated `chrome.alarms` entry (`cdnwaf-ip-refresh`, `periodInMinutes: 1440`) so the refresh actually fires daily regardless of how long the browser session runs between service-worker restarts.

### Added — crowd-report feedback loop (read side)
New `fetchCrowdReports()` in background.js (cached 10 min per provider) calls the Worker's existing `GET /reports?provider=ID` and surfaces the results in each provider's detail view: report counts, tallied by note text, with anything matching this exact scan's own unrecognized headers highlighted ("also seen on this scan!"). Closes the loop the crowd-reporting feature always implied — you could report something unusual, but had no way to see whether anyone else had reported the same thing. **Deliberately informational only**: the Worker's `/report` and `/reports` endpoints have no authentication (documented in `worker/README.md`), so this data is unverified and is never fed into detection scoring or verdicts — only displayed as context.

## v9.5.5 — GitHub-based update checker (Chrome build only)

Chrome gives extensions no API to overwrite their own installed files — true even in unpacked/"Load unpacked" dev mode — so a silent, fully-automatic self-update the way a Tampermonkey userscript does via `@updateURL` isn't achievable here. What's implemented instead: once a day (plus once on service-worker startup), `checkForUpdate()` fetches `manifest.json` from this repo's `main` branch (`raw.githubusercontent.com/VuJohn123/Chrome_CDNs_WAFs_Detector/main/manifest.json`) and compares its `version` against the installed one. If the repo is ahead, a banner appears in the popup ("⬆ Update available: vX.X.X...") that opens the repo page on tap — the person still downloads and reloads the extension themselves; there's no way around that last step.

No new manifest permission was needed (`<all_urls>` in `host_permissions` already covers `raw.githubusercontent.com`). Skipped entirely on Firefox — an AMO-distributed extension already gets real, silent auto-updates through Firefox's own add-on manager, so a "go get it from GitHub" banner there would point at the wrong install path and just cause confusion.

## v9.5.6 — Version-tag staleness, theme flash, domain-suffix detection, small text

### Fixed — the popup header and Settings footer both said "v9.1" for real
Both were hardcoded strings that never got touched across every version bump since v9.1, including all the ones in this same conversation. Both now read `chrome.runtime.getManifest().version` at render time. The Settings "About" line's claim of "no telemetry by default" was also stale (crowd reporting has defaulted to on since v9.5.3) — corrected.

### Fixed — flash of wrong theme on every popup open
Theme was applied only after an async `chrome.storage.local` round-trip, so every popup open briefly rendered the wrong theme before flipping to the correct one. `chrome.storage.local` is still the source of truth, but `applyTheme()` now also writes a same-session `localStorage` cache, and a new synchronous block at the very top of `popup.js` reads that cache and applies the theme before anything else runs — eliminating the flash. (`localStorage` is genuinely available here — it's an extension page in the browser, not the sandboxed Artifacts environment where it's disallowed.)

### Added — domain-suffix detection (no CNAME required)
CNAME-pattern matching (`p.cnamePatterns`) previously only ran against a domain's *resolved CNAME target* — so scanning a platform hostname directly (e.g. a bare `*.vercel.app`, `*.up.railway.app`, or `*.appspot.com` address, which typically resolves via A/AAAA with no CNAME hop at all) never matched, even though the domain itself unambiguously *is* that platform's own hostname. The same `cnamePatterns` regexes are now also tested directly against the scanned domain string. Zero new pattern lists (reuses exactly what each provider already declared), zero risk of new false positives (exact-suffix match only), and it's a no-op for any domain that doesn't end in one of these already-narrow, provider-specific suffixes.

### Changed — smallest UI text bumped up a size
`.breakdown-note`, `.settings-hint`, `.settings-section-title`, and a few other classes were set to 9px/9.5px — genuinely hard to read in a browser-action popup. Bumped every 9px/9.5px declaration in `style.css` to 10px/10.5px (16 declarations total). Left 10px+ alone.

### Investigated, no change needed
A real-world Cloudflare + Google-fronted domain (Padlet, via an uploaded HAR-style request/response dump) was used to sanity-check current detection against real traffic: `cf_clearance`/`__cf_bm` cookies were already scored (Cloudflare Bot Management), the `via: 1.1 google` + GKE backend headers were already correctly detected as Google Cloud/GFE infrastructure, and the site's own custom application headers were correctly left unclassified as provider-unrecognized rather than false-matched to any CDN. No gap found in this sample.

## v9.5.7 — Fix cross-provider header misattribution + toolbar/settings grouping

### Fixed — reporting an unrecognized header could misattribute it to the wrong provider
Real bug, caught by testing against the Padlet sample above: `result.unknownHeaders` is one global list for the whole scan, but the "Help improve this signature" report UI was rendering that *identical* list on **every detected provider's page** — Cloudflare, Google, and Akamai all showed the same 9 headers with a one-click "report to this provider" button. A header like `ww-cat` (clearly Padlet's own application header) could get reported as a Cloudflare signal just because the Cloudflare page happened to be open, or worse, reported against Akamai at a tentative 53% confidence. There's no way to know for certain which layer (edge/CDN vs. origin app) an arbitrary header name belongs to, so the fix narrows rather than pretends to solve it precisely: the report buttons for unrecognized headers now only appear on the single most-confidently-detected provider's page for that scan (computed from `verdict.score` across all detected providers), with copy that says outright these headers might belong to the origin app rather than this provider — use your judgment. Other providers' pages now link over to that provider's name instead of offering the same buttons. The free-text note field (a deliberate, considered claim rather than a reflexive click) is left available everywhere.

### Changed — toolbar and Settings reorganized
The main popup's 6-button toolbar row (Pinned / Batch scan / Compare / Settings / Watchlist / Open as side panel) is now two rows: scan-workflow tools (Pinned, Batch scan, Compare) on top, view/app-level actions (Watchlist, Open as side panel, Settings) below a thin divider. In Settings, "Import a scan code" and "Threat intel API keys" are now grouped under an "— Advanced —" label, and "About" moved to the very end as a footer section instead of being sandwiched in the middle.

## v9.5.8 — Update-checker repo move

Chrome and Firefox source moved from two separate repos into one combined repo (`VuJohn123/CDNs_WAFs_Detector`, with `Chrome_CDNs_WAFs_Detector/` and `FireFox_CDNs_WAFs_Detector/` as subfolders). Updated `UPDATE_REPO_MANIFEST_URL`/`UPDATE_REPO_HTML_URL` in `background.js` (added in v9.5.5) to match — `manifest.json` is no longer at the repo root, so the old URL would have 404'd forever. Chrome-only, as before (see v9.5.5).

## v9.5.9 — Crowd reports now include domain, scan watchdog

### Changed — crowd reports now include the domain (deliberate privacy trade-off)
Reported that the same 6-9 "unrecognized header" names showed up identically across every high-confidence provider on a given scan, with no way to tell whether a header is genuinely that provider's own signal or just that particular site's own application header. Fix: crowd reports now include the domain the header was seen on (`maybeSubmitCrowdReport()`, the Worker's `POST /report`, and its KV-stored report shape all updated). The dashboard's per-provider table now shows a distinct-domain count per note — a header reported across many unrelated domains is real corroborating evidence it's a provider-wide signal; one that only ever shows up on a single domain almost certainly isn't. This is a genuine, disclosed privacy change: the extension's Settings copy previously said reports "never" include your domain — that's no longer true, and the copy (both in Settings and right at the report buttons themselves) now says so plainly, with an explicit warning line and an easy way to turn reporting off. `worker/README.md` and the dashboard's own header text were updated to match — the dashboard is no longer described as "anonymous."

### Added — scan watchdog timeout
Reported: the popup occasionally gets stuck on "Connecting… 0%" indefinitely, with console errors referencing the background script and a tab that no longer exists. Root cause wasn't reproducible from the description alone (no exact error text to go on — a full DevTools console screenshot next time it happens would help pin it down further), but a defensive fix was added regardless: `doScan()` now arms a 25-second watchdog when the scan port connects, reset on every message received. If nothing at all arrives (no progress tick, no result, no error) within that window, the scan is treated as stalled — the port is dropped and the UI shows "Scan stalled with no response — try again" instead of hanging forever.

## v9.5.10 — Report-attribution tie fix, soft-404 false-positive guard, probe concurrency

### Fixed — report buttons missing when two providers tie at the top score
Screenshot showed Cloudflare and CloudFront both at 100%, but the report UI only appeared on Cloudflare's page. The v9.5.7 fix picked a single "top provider" via a sort, which silently drops any other provider tied at the same score. `topProviderId` is now `topProviderIds` (a Set of every provider tied at the max score); the gating check and the referral message on non-top pages both updated to handle ties correctly.

### Fixed — 4 Cloudflare probes could false-positive on SPA catch-all routing
Reported concern: if an endpoint like `/cdn-cgi/...` returns HTTP 200 but the body is actually a generic "not found" page, that's a false signal. `/cdn-cgi/trace` itself was already safe (its strong signal requires the body to contain `colo=`), but `/cdn-cgi/challenge-platform/`, `/cdn-cgi/rum`, and `/cdn-cgi/zaraz/i.js` trusted a 200 status code alone — worth 24+20+22 = 66 points combined, plus another 35 from `/cdn-cgi/trace`'s weak signal, all riding on status code only. A domain whose origin does SPA-style catch-all routing (200 + the same HTML shell for literally any unmatched path — common with client-side routers) could trigger all of these simultaneously with zero relation to Cloudflare. Added a shared `self._looksLikeGenericHtmlFallback()` helper (checks for a `<!doctype html>`/`<html>` shell) and applied it to all 4 probes, plus Akamai's `/_mPulse/api/v1/` (an API endpoint that shouldn't legitimately return an HTML page). Deliberately did **not** apply the same check to Akamai's `/akamai/sureroute-test-object.html` probe — that file is legitimately HTML by Akamai's own design, and applying a blanket HTML-shell heuristic there risks a false negative without verified knowledge of its exact real-world response format.

### Changed — probe concurrency 6 → 8
All probes in a scan hit the same origin, which HTTP/2+ multiplexes over one connection — raising concurrency doesn't meaningfully increase risk of overwhelming the target the way it would across many different origins. Modest speedup for domains that match many providers' probe sets. Audited the rest of the scan pipeline for the same class of issue (unnecessary sequential awaits): Phase 1 (DNS/cookies/SPF/anycast) already runs fully parallel via `Promise.all`; Phase 2 (apex + www fetch) is deliberately sequential — it measures per-request timing to detect a challenge/JS-injection layer, which the sequential ordering is required for. No other change made there.

## v9.5.11 — More soft-404 false positives, confirmed by real testing

Follow-up to v9.5.10, prompted by a real test result: `claude.ai/akamai/sureroute-test-object.html` returns HTTP 200 with a generic "Page not found" body, and the old code ticked Akamai's SureRoute signal green anyway — proving the earlier caution about leaving that specific probe unguarded (on the theory that the real test object is legitimately HTML) was wrong in practice. Fixed, using the same `self._looksLikeGenericHtmlFallback()` guard as the other probes.

A follow-up sweep across all 24 provider files (broader pattern match than v9.5.10's, to catch probes formatted differently) found 2 more unguarded Cloudflare probes that were missed the first pass: `/cdn-cgi/waitingroom/` (+20 points) and `/cdn-cgi/access/` (+32 points), both trusting a 200 status with zero content check. Both fixed the same way. Re-ran the sweep after fixing — nothing left unguarded across any provider.

## v9.5.12 — 25th provider: Deno Deploy (researched)

Researched the current CDN/edge-hosting landscape for anything genuinely new and missing. Findings:
- **Edgio** (formerly Limelight/Edgecast) — confirmed defunct, ceased operations January 2025. Not worth adding a provider for a shut-down service.
- **Deno Deploy** — a real gap. Deno's own docs confirm two domain families: the "Classic" platform's default preview URLs at `*.deno.dev` (Classic itself was shut down July 20, 2026, but existing sites CNAME'd to a `.deno.dev` target will keep resolving there for a while yet), and the current platform's default org domain at `*.deno.net`. Added as a 25th provider (`denodeploy.js`), modeled directly on `render.js`'s conservative pattern: domain-suffix detection only (both `.deno.dev$` and `.deno.net$`, both verified against Deno's official documentation), with **no invented header signals** — there's no public documentation of a Deno-specific response header the way there is for `x-vercel-id` or `cf-ray`, so none was guessed at. Registered in `background.js` (`importScripts`), `provider-meta.js` (batch/compare pages), and `popup.js` (`PROVIDER_UI`).
- Also fixed while touching this: the manifest description still said "24" providers and referenced "Core Web Vitals attribution," a feature removed as dead code back in v9.5.3. Now says 25 and mentions crowd-sourced signature reporting instead.

Considered and set aside: BlazingCDN (a newer, cost-focused entrant per recent market coverage) — no verified technical signal (headers, IP ranges, or domain pattern) found to detect it by, so nothing was added rather than guessing.

## v9.5.13 — New signal: RFC 9213 vendor-scoped cache-control header

Researched what's genuinely new in the CDN/WAF space rather than repeating already-covered ground. Found: **RFC 9213 "Targeted HTTP Cache Control"** — a finalized, published RFC (not a draft) co-authored by engineers from Akamai, Fastly, and Cloudflare, defining a generic `CDN-Cache-Control` response header plus vendor-scoped variants like `Cloudflare-CDN-Cache-Control`. Confirmed via a source dated June 2026 that Cloudflare has actually shipped the vendor-scoped variant and processes it in preference to the generic one when both are present.

Added `cloudflare-cdn-cache-control` detection to `cloudflare.js` as a new signal (`cfCacheControlHeader`, +30 points) — vendor-prefixed, so exclusive to Cloudflare when present, per current documentation. Scored moderately rather than as a top-tier signal since it's an opt-in per-zone cache feature, not universal — its absence proves nothing, only its presence is informative. The generic (non-prefixed) `cdn-cache-control` header was added to `knownHeaders` so the unknown-header detector doesn't flag it as unrecognized, but it isn't scored on its own since it's shared across any RFC 9213–supporting CDN, not Cloudflare-exclusive.

Deliberately did **not** add a similar check for Akamai's vendor-scoped variant — the only source found naming one used an older (2021) name that may not reflect Akamai's actual current header, and guessing at an unverified header name would violate the project's own "no fabricated signals" rule. Worth revisiting if a more current, confirmed source turns up.

## v9.5.14 — Heroku (26th provider), taxonomy-tree registration gap, stability/performance re-audit

### Added — Heroku
Researched: still an active, live PaaS (Salesforce subsidiary, replatformed onto Kubernetes in 2024, ongoing as of 2026 — not defunct). Added `heroku.js` on the same conservative pattern as Render/Railway/Deno Deploy: domain-suffix matching only (`.herokuapp.com$`, `.herokudns.com$`, both from Heroku's own DevCenter docs). Heroku's router does add an `X-Request-ID` header, but that name is generic enough that unrelated services also use it — not treated as an exclusive signal, so it isn't checked.

### Fixed — new providers were invisible in the 4-layer taxonomy tree
Re-running the "does every provider appear everywhere it should" check (the same class of bug fixed for Fly.io/Render/Railway back in v9.5.3) turned up a 5th registration point that had been missed for the two newest providers: the taxonomy tree's `TAXONOMY[].ids` arrays are a separate, hardcoded grouping from `PROVIDER_UI`, and Deno Deploy + Heroku were in `PROVIDER_UI` (so visible in the overview grid) but absent from the `hosting` group's `ids` list — meaning either would score correctly but never appear in the 4-layer tree view. Both added to the `hosting` group alongside Vercel/Netlify/Fly.io/Render/Railway. Verified programmatically afterward: all 26 providers now appear in exactly one taxonomy group.

### Verified stable — full re-audit
- Full `node --check` sweep across every `.js` file in both builds — clean.
- Both `manifest.json` files valid, Firefox `gecko.id` unchanged.
- Cross-checked provider registration across all 5 places a provider needs to exist (`CDN_PROVIDERS` in its own file, `importScripts`, `provider-meta.js`, `PROVIDER_UI`, `TAXONOMY`) — 26/26 consistent everywhere.
- Re-ran the message-action parity check (every `sendMessage`/port call in `popup.js`/`batch.js`/`compare.js`/`offscreen.html` against every handler in `background.js`) — clean, only the already-known, intentionally-unwired `previewCustomRule` remains.
- Re-ran the soft-404 probe sweep across all 26 provider files — nothing unguarded.
- No duplicate top-level declarations in `background.js` or `popup.js`.
- CSS: confirmed no regression back to sub-9px text.

### Performance — investigated, no change needed
Checked `ipMatches()` (the IP-range-matching hot path) for an algorithmic bottleneck given the provider count grew from 24 to 26. It's a linear scan, but only ~4-8 resolved IPs are checked against the 5 providers that currently have non-trivial CIDR lists (Cloudflare, Fastly, CloudFront, Google, BunnyCDN) — worst case a few thousand cheap numeric range comparisons, sub-millisecond in practice. Not a real bottleneck; adding a trie/radix structure or similar here would be complexity for no measurable benefit, so nothing was changed.

## v9.5.15 — Accessibility pass, i18n verified, Early Hints researched (not implementable)

### Added — screen-reader announcements for scan status/progress
`popup.html`'s static toolbar buttons already had proper `aria-label`/`aria-hidden` — that part was solid. The gap was dynamic content: the status line and progress indicator update constantly during a scan with no way for a screen reader to know unless the user manually navigates to check. Added `role="status" aria-live="polite"` to both. Deliberately did **not** add `aria-live` to the large `#results` container — that would force screen readers to re-announce entire multi-hundred-line detail views on every click (switching providers, opening Settings), which is worse than saying nothing. The right pattern here is a brief, meaningful status announcement, with the user navigating into the detail on their own terms afterward — not force-reading everything.

### Verified — i18n already complete
Compared every key in `_locales/en/messages.json` against `_locales/vi/messages.json`: 36/36 match exactly both directions, nothing missing either side. No fix needed — good to have confirmed rather than assumed.

### Researched, not implementable — Early Hints (HTTP 103)
A real, increasingly-deployed signal (RFC 8297; Cloudflare, Fastly, and Google all document support) — but a dead end for this extension specifically: 103 is a 1xx *interim* response, and the Fetch API a browser extension uses (`fetch()`) never exposes interim responses to JavaScript at all — the browser consumes and discards them internally before the `Response` object (representing only the final 200/404/etc.) is handed back. `chrome.webRequest` doesn't expose 1xx responses to extensions either. This isn't a code gap to fix — it's a platform limitation with no available workaround, so nothing was added rather than pretending otherwise.

## v9.5.16 — Score-over-time sparkline chart in the Timeline view

Bigger-picture idea rather than another incremental fix: the Timeline view (D1) already stores a full snapshot on every scan, specifically for diffing — but it only ever surfaced that history as a text list of dates and provider-name changes. Added `renderScoreSparkline()`: a compact, hand-built SVG line chart (no charting library — MV3's CSP doesn't allow one anyway) plotting every provider that was ever detected across the domain's scan history, score (0-100%) on the Y axis, chronological on the X axis, using each provider's own brand color for its line so it's instantly scannable which line is which. Hover a point for the exact score and timestamp. Skips the chart entirely for domains with fewer than 2 snapshots (a single point isn't a trend). Inserted above the existing text-based snapshot list — the list still exists for the exact per-change detail; the chart is for spotting *that* something changed, and roughly when, at a glance. No new storage or backend work required — this is purely a new view over data that was already being collected.

## v9.5.17 — Fixed the real "No tab with id" bug + Test Connection button

### Fixed — the "Uncaught (in promise) Error: No tab with id: X" bug, finally with a real error message to work from
Root cause found: `ambientHeadersListener()`'s `chrome.action.setBadgeText()`/`setBadgeBackgroundColor()` calls (and a matching pair in the `chrome.tabs.onUpdated` listener) were fire-and-forget — not `await`ed. Both were sitting inside a `try/catch`, but that only catches *synchronous* throws at call time; the actual rejection happens later, asynchronously, after the tab has already closed mid-request (a normal thing to happen — this listener fires on `webRequest.onHeadersReceived`, which can resolve after the user has already closed the tab). Since the promise rejection happened outside the try block's synchronous window, it surfaced as a genuinely unhandled rejection. Fixed by attaching `.catch(() => {})` to both calls at both sites, rather than `await`ing them (which would add blocking latency to a listener that fires on every single response header this feature cares about). Swept the rest of `background.js` for the same pattern (any `chrome.action.setBadge*`/`chrome.tabs.sendMessage`/`chrome.tabs.get` call missing both `await` and `.catch(`) — nothing else found.

### Added — "Test connection" button for the crowd-report endpoint
Directly motivated by real friction from earlier in this project: multiple round-trips were spent just figuring out whether the Worker was actually deployed and reachable. New button next to the endpoint field in Settings does a plain `GET` against the endpoint's dashboard root (never a fake `POST /report` — this doesn't write any test data into real report storage) and reports back reachable/unreachable with the HTTP status or error, in place.

## v9.5.18 — 5-item improvement list, all delivered

Requested list from last round, all implemented:

### 1. Sparkline chart on the Compare page
Same hand-built SVG approach as the Timeline view's chart (v9.5.16), applied to `compare.js`: after both domains are scanned, a 2-line trend chart plots detected-provider count over time for domain A vs domain B (using `getSnapshotHistory`, already stored — no new backend). Individual per-provider lines weren't used here (26 lines × 2 domains would be unreadable) — provider count is the meaningful comparison at this zoom level. Hidden when either domain has fewer than 2 stored snapshots to trend from.

### 2. First-run onboarding card
A lightweight, dismissible inline card (not a blocking modal) shown once on fresh installs (`chrome.runtime.onInstalled` with `reason === 'install'`, not on updates), covering the core workflow in 4 short steps. One click to dismiss and it's gone permanently — never gets in the way of someone who just wants to start scanning immediately.

### 3. Diagnostics ("Run diagnostics" button in Settings)
Checks, in one pass: all 3 DoH resolvers' reachability and latency, IP-range cache freshness, a real local-storage read/write round-trip, and the crowd-report Worker's reachability (skipped if reporting is off). Directly motivated by the real friction earlier in this project — figuring out "is X actually working" one piece at a time by trial and error.

### 4. CSV import for batch scanning
Turned out this already existed (`csvUpload` in `batch.html`/`batch.js`) — nothing to add. Found and fixed two real bugs while checking it, though: `batch.html`, `compare.html`, and `sidepanel.html` still had the same hardcoded "v9.1" the popup header had (fixed back in v9.5.6, but missed in these three files) — now all four read the version dynamically from the manifest. Also removed genuinely dead code in `batch.js`: a block reading `batch_prefill_domains` from storage, left over from a "batch from bookmarks/tabs" feature removed back in v9.5.0 — nothing has written that key since, and `runStorageMigration()` actively deletes it on every startup anyway.

### 5. Unit tests for provider scoring
New `test/run-tests.js` — runs with plain `node test/run-tests.js`, no dependencies, no build step. It polyfills the `self` global providers register onto and evaluates the actual shipped provider files directly (not a reimplementation), then checks: empty signals never claim detection, scores are always clamped to [0, 100] even with every boolean signal forced true, every provider has a valid name/color, and no two providers share an id. Verified this isn't a rubber-stamp test suite by deliberately injecting a scoring bug into a copy of `cloudflare.js`, confirming the suite caught it (182/183 passed, the injected bug flagged), then restoring the real file and confirming 183/183 again.

All 26 providers currently pass all checks (183/183).
