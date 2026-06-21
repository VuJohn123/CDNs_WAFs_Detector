// ============================================================
// Multi-CDN/WAF Detector — background.js  v8.1
// 2026 update: resilient multi-provider DoH fallback, NS lookup,
// stricter signal scoring, common-header expansion, shared ALPN probe
//
// CROSS-BROWSER NOTE (Chrome / Edge / Opera / Firefox, all MV3):
// - Uses `self` (not `window`) for shared globals — valid in both the
//   Chromium service-worker context and Firefox's background-page fallback.
// - Uses `chrome.*` namespace — Firefox aliases `chrome` to `browser`
//   automatically, and every API called here (storage, cookies, runtime)
//   is Promise-compatible on both, so no callback/Promise branching needed.
// - `importScripts()` works identically in a Chromium service worker and
//   in Firefox's non-module background script (manifest's "scripts" key).
// - No localStorage/sessionStorage/DOMParser — unavailable in service
//   workers and intentionally avoided so the same file runs unmodified
//   under either background mode declared in manifest.json.
// ============================================================

importScripts(
  'cloudflare.js',
  'google.js',
  'akamai.js',
  'fastly.js',
  'imperva.js',
  'cloudfront.js',
  'azure.js',
  'sucuri.js',
  'vercel.js',
  'netlify.js',
  'bunnycdn.js',
  'stackpath.js',
  'keycdn.js',
  'gcore.js',
  'datadome.js',
  'perimeterx.js',
  'f5distributed.js',
  'tencenteo.js',
  'alicdn.js',
  'arvancloud.js',
  'vncdn.js'
);

// ── Constants ─────────────────────────────────────────────────
const WEEK_MS          = 7 * 24 * 60 * 60 * 1000;
const CACHE_TTL_MS     = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;
const PROBE_TIMEOUT_MS = 6000;
const DOH_TIMEOUT_MS   = 6000;
const PROBE_CONCURRENCY = 6;

// Bump this whenever scoring/signal logic changes meaningfully, so existing
// cache entries (which may reflect outdated logic) are invalidated automatically.
const ENGINE_VERSION = 2;

// A lightweight hash of the active provider set + engine version. Cache
// entries are keyed against this so that loading new/updated provider
// files (different probe count, different ids) naturally busts stale cache
// instead of silently returning results scored under old rules.
function computeRulesHash() {
  const providers = self.CDN_PROVIDERS || [];
  const sig = providers
    .map(p => `${p.id}:${(p.probes || []).length}:${(p.cnamePatterns || []).length}`)
    .sort()
    .join('|');
  let h = 0;
  const full = `${ENGINE_VERSION}|${sig}`;
  for (let i = 0; i < full.length; i++) h = (h * 31 + full.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

// Multi-provider DoH fallback — if Cloudflare DoH fails, try Google, then NextDNS
// All are RFC 8484 compliant. We try in order and use the first success.
const DOH_PROVIDERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.nextdns.io/dns-query'
];

// ── CIDR matching ─────────────────────────────────────────────
function ip4Int(ip) {
  return ip.split('.').reduce((a, o) => (a * 256 + parseInt(o, 10)) >>> 0, 0);
}
function inCIDR4(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = (0xffffffff << (32 - +bits)) >>> 0;
  return (ip4Int(ip) & mask) === (ip4Int(base) & mask);
}

// Full IPv6 -> 128-bit BigInt, expanding "::" correctly regardless of
// where it occurs (start/middle/end) and how many groups it elides.
function ip6ToBigInt(ip) {
  const clean = ip.split('%')[0]; // strip zone index if present
  let head = [], tail = [];
  if (clean.includes('::')) {
    const [h, t] = clean.split('::');
    head = h ? h.split(':') : [];
    tail = t ? t.split(':') : [];
  } else {
    head = clean.split(':');
  }
  const missing = 8 - head.length - tail.length;
  const groups = [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail];
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g || '0', 16));
  return n;
}
function inCIDR6(ip, cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = +bitsStr;
  const ipN   = ip6ToBigInt(ip);
  const baseN = ip6ToBigInt(base);
  const mask  = bits === 0 ? 0n : (((1n << 128n) - 1n) << BigInt(128 - bits)) & ((1n << 128n) - 1n);
  return (ipN & mask) === (baseN & mask);
}
function ipMatches(ip, v4, v6) {
  if (!ip) return false;
  try {
    if (ip.includes(':')) return (v6 || []).some(c => inCIDR6(ip, c));
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return (v4 || []).some(c => inCIDR4(ip, c));
  } catch { /* malformed IP/CIDR — treat as no match */ }
  return false;
}

// ── Timeout fetch ─────────────────────────────────────────────
async function fetchT(url, opts = {}, ms = FETCH_TIMEOUT_MS) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

// ── DoH query with multi-provider fallback ───────────────────
// Returns parsed JSON or null. Tries each provider in order.
async function doh(domain, type) {
  for (const provider of DOH_PROVIDERS) {
    try {
      const res = await fetchT(
        `${provider}?name=${encodeURIComponent(domain)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' }, cache: 'no-store' },
        DOH_TIMEOUT_MS
      );
      if (res.ok) {
        const json = await res.json();
        // Validate we got a real DNS response structure
        if (json && typeof json.Status === 'number') return json;
      }
    } catch { /* try next provider */ }
  }
  return null;
}

// ── Unified DNS lookup: A, AAAA, CNAME, MX, NS, TXT ─────────
// Returns { ips, cname, mxRecords, nsRecords, txtRecords, minTTL }
// NS is used for vanity-NS CDN detection (Cloudflare, Azure, etc.)
// TXT is used for verification tokens (Google, Azure, etc.)
async function doHLookup(domain) {
  const ips    = [];
  let   cname  = null;
  const mx     = [];
  const ns     = [];
  const txt    = [];
  let   minTTL = Infinity;

  await Promise.allSettled([
    doh(domain, 'A').then(d => {
      for (const r of (d?.Answer || [])) {
        if (r.type === 1) {
          const ip = r.data.trim();
          if (!ips.includes(ip)) ips.push(ip);
          if (r.TTL < minTTL) minTTL = r.TTL;
        }
        // A query also returns CNAMEs in Answer section
        if (r.type === 5 && !cname) cname = r.data.toLowerCase().replace(/\.$/, '');
      }
    }),
    doh(domain, 'AAAA').then(d => {
      for (const r of (d?.Answer || [])) {
        if (r.type === 28) {
          const ip = r.data.trim().toLowerCase();
          if (!ips.includes(ip)) ips.push(ip);
          if (r.TTL < minTTL) minTTL = r.TTL;
        }
        if (r.type === 5 && !cname) cname = r.data.toLowerCase().replace(/\.$/, '');
      }
    }),
    doh(domain, 'CNAME').then(d => {
      // Explicit CNAME query — overrides any cname found above if both present
      const rec = (d?.Answer || []).find(r => r.type === 5);
      if (rec) cname = rec.data.toLowerCase().replace(/\.$/, '');
    }),
    doh(domain, 'MX').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 15) {
          const host = (r.data.trim().split(/\s+/)[1] || '').toLowerCase().replace(/\.$/, '');
          if (host && !mx.includes(host)) mx.push(host);
        }
    }),
    doh(domain, 'NS').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 2) {
          const host = r.data.trim().toLowerCase().replace(/\.$/, '');
          if (host && !ns.includes(host)) ns.push(host);
        }
    }),
    doh(domain, 'TXT').then(d => {
      for (const r of (d?.Answer || []))
        if (r.type === 16) txt.push((r.data || '').replace(/^"|"$/g, '').toLowerCase());
    }),
  ]);

  return {
    ips,
    cname,
    mxRecords:  mx,
    nsRecords:  ns,
    txtRecords: txt,
    minTTL: minTTL === Infinity ? null : minTTL
  };
}

// ── NS pattern matching (providers that use vanity NS) ────────
const NS_PATTERNS = [
  { re: /\.ns\.cloudflare\.com$/, signal: 'cfCname',     pid: 'cloudflare' },
  { re: /\.cloudflare\.com$/,     signal: 'cfCname',     pid: 'cloudflare' },
  { re: /akam\.net$/,             signal: 'akamaiCname', pid: 'akamai'     },
  { re: /akamaiedge\.net$/,       signal: 'akamaiCname', pid: 'akamai'     },
  { re: /awsdns-/,                signal: 'cloudfrontIP',pid: 'cloudfront'  }, // Route 53 NS → likely CloudFront
  { re: /azure-dns\./,            signal: 'azureCname',  pid: 'azure'       },
];

// ── IP / domain input detection ───────────────────────────────
function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) &&
    s.split('.').every(o => +o >= 0 && +o <= 255);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
}
function isIPLiteral(s) {
  return isIPv4(s) || isIPv6(s);
}

// ── Reverse DNS (PTR) via DoH ─────────────────────────────────
function ipToPtrName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  if (isIPv6(ip)) {
    // Expand to full 8-group form, then nibble-reverse for ip6.arpa
    const parts = ip.split('::');
    let groups;
    if (parts.length === 2) {
      const head = parts[0] ? parts[0].split(':') : [];
      const tail = parts[1] ? parts[1].split(':') : [];
      const fill = Array(8 - head.length - tail.length).fill('0');
      groups = [...head, ...fill, ...tail];
    } else {
      groups = ip.split(':');
    }
    const nibbles = groups.map(g => g.padStart(4, '0')).join('').split('').reverse();
    return nibbles.join('.') + '.ip6.arpa';
  }
  return null;
}

async function reversePtr(ip) {
  const name = ipToPtrName(ip);
  if (!name) return null;
  try {
    const d = await doh(name, 'PTR');
    const rec = (d?.Answer || []).find(r => r.type === 12);
    return rec ? rec.data.toLowerCase().replace(/\.$/, '') : null;
  } catch { return null; }
}

// ── RDAP (ASN / org) lookup — replaces legacy whois, no API key needed ─
// Uses the IANA RDAP bootstrap redirector which is publicly accessible.
async function rdapLookup(ip) {
  try {
    const res = await fetchT(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json' }
    }, 7000);
    if (!res.ok) return null;
    const j = await res.json();
    const org = (j.entities || [])
      .flatMap(e => e.vcardArray?.[1] || [])
      .find(v => v[0] === 'fn')?.[3] || j.name || null;
    const asnHandle = j.handle || null;
    const cidr = Array.isArray(j.cidr0_cidrs) && j.cidr0_cidrs[0]
      ? `${j.cidr0_cidrs[0].v4prefix || j.cidr0_cidrs[0].v6prefix}/${j.cidr0_cidrs[0].length}`
      : null;
    return { org, asnHandle, cidr, country: j.country || null };
  } catch { return null; }
}

// ── Cross-verification: for each resolved IP, gather PTR + RDAP evidence
// and check it against provider CNAME/NS hints already collected in allSig.
// This produces independent corroboration that isn't based on header spoofing.
async function buildIpEvidence(ips, providers) {
  const evidence = {};
  await runPooled(ips, PROBE_CONCURRENCY, async ip => {
    const [ptr, rdap] = await Promise.all([reversePtr(ip), rdapLookup(ip)]);
    const matchedProviders = [];
    if (ptr) {
      for (const p of providers) {
        for (const { re, signal, pid } of (p.ptrPatterns || [])) {
          if (re.test(ptr)) matchedProviders.push(pid || p.id);
        }
      }
      // Also reuse NS_PATTERNS-style org/ptr hints embedded per-provider via cnamePatterns
      // when the PTR hostname itself looks like a CDN edge node.
      for (const p of providers) {
        for (const { re, signal } of (p.cnamePatterns || [])) {
          if (re.test(ptr)) matchedProviders.push(p.id);
        }
      }
    }
    if (rdap?.org) {
      const orgLower = rdap.org.toLowerCase();
      for (const p of providers) {
        if ((p.orgNames || []).some(n => orgLower.includes(n))) matchedProviders.push(p.id);
      }
    }
    evidence[ip] = {
      ptr,
      org: rdap?.org || null,
      asnHandle: rdap?.asnHandle || null,
      cidr: rdap?.cidr || null,
      country: rdap?.country || null,
      matchedProviders: [...new Set(matchedProviders)]
    };
  });
  return evidence;
}


function parseIPList(p, text, family) {
  if (p.ipConfig?.parseResponse) return p.ipConfig.parseResponse(text, family);
  return text.trim().split('\n').map(l => l.trim()).filter(Boolean);
}

async function refreshAllIPRanges() {
  const providers = self.CDN_PROVIDERS || [];
  await Promise.allSettled(providers.filter(p => p.ipConfig?.v4Url).map(async p => {
    try {
      const ic = p.ipConfig;
      const r4 = await fetchT(ic.v4Url, {}, 10000);
      if (!r4.ok) return;
      const txt4 = await r4.text();
      const p4   = parseIPList(p, txt4, 'v4');
      if (p4.length) ic.v4 = p4;

      if (ic.singleFile) {
        const p6 = parseIPList(p, txt4, 'v6');
        if (p6.length) ic.v6 = p6;
      } else if (ic.v6Url) {
        const r6 = await fetchT(ic.v6Url, {}, 10000);
        if (r6.ok) {
          const p6 = parseIPList(p, await r6.text(), 'v6');
          if (p6.length) ic.v6 = p6;
        }
      }

      if (ic.storageKey)
        await chrome.storage.local.set({ [ic.storageKey]: { v4: ic.v4, v6: ic.v6 } });
    } catch {}
  }));
}

async function loadCachedRanges() {
  const providers = self.CDN_PROVIDERS || [];
  const keys = providers.filter(p => p.ipConfig?.storageKey).map(p => p.ipConfig.storageKey);
  if (!keys.length) return;

  const stored = await chrome.storage.local.get(['ip_refresh_ts', ...keys]);
  for (const p of providers) {
    const cache = p.ipConfig?.storageKey && stored[p.ipConfig.storageKey];
    if (cache?.v4) p.ipConfig.v4 = cache.v4;
    if (cache?.v6) p.ipConfig.v6 = cache.v6;
  }

  const lastTs = stored.ip_refresh_ts || 0;
  if (Date.now() - lastTs > WEEK_MS) {
    refreshAllIPRanges()
      .then(() => chrome.storage.local.set({ ip_refresh_ts: Date.now() }))
      .catch(() => {});
  }
}

// ── Scan result cache ─────────────────────────────────────────
function cacheKey(domain) {
  return `scan_${domain}_${computeRulesHash()}`;
}
async function getCached(domain) {
  try {
    const key = cacheKey(domain);
    const d = await chrome.storage.local.get(key);
    const e = d[key];
    if (e && Date.now() - e.ts < CACHE_TTL_MS) return e.result;
  } catch {}
  return null;
}

async function setCached(domain, result) {
  try {
    await chrome.storage.local.set({ [cacheKey(domain)]: { ts: Date.now(), result } });
  } catch {}
}

// ── Scan history (separate from the short-lived cache; kept until user clears it) ─
const HISTORY_KEY      = 'scan_history';
const HISTORY_MAX_ITEMS = 50;

async function addToHistory(domain, result) {
  try {
    const detected = Object.entries(result.providers || {})
      .filter(([, v]) => v.verdict?.detected)
      .map(([id]) => id);
    const entry = {
      domain,
      ts: Date.now(),
      detected,
      ipCount: (result.resolvedIPs || []).length,
      isDirectIP: !!result.isDirectIP
    };
    const { [HISTORY_KEY]: existing = [] } = await chrome.storage.local.get(HISTORY_KEY);
    // Remove any prior entry for the same domain, then prepend the fresh one
    const next = [entry, ...existing.filter(e => e.domain !== domain)].slice(0, HISTORY_MAX_ITEMS);
    await chrome.storage.local.set({ [HISTORY_KEY]: next });
  } catch {}
}

async function getHistory() {
  try {
    const { [HISTORY_KEY]: list = [] } = await chrome.storage.local.get(HISTORY_KEY);
    return list;
  } catch { return []; }
}

async function clearHistory() {
  try { await chrome.storage.local.remove(HISTORY_KEY); } catch {}
}

// ── Shared common-header extraction ──────────────────────────
// Called once per HTTP response; result is merged into every provider's signals.
function extractCommonSignals(res) {
  const hR = n => res.headers.get(n) || '';
  const h  = n => hR(n).toLowerCase();

  // Server-Timing: Cloudflare now emits cfL4, cfWorker, cdn-cache sub-metrics.
  // We flag presence generically — individual providers narrow this down.
  const st = hR('server-timing');

  return {
    hasAge:               res.headers.has('age'),
    hasSMaxAge:           /s-maxage\s*=\s*\d+/i.test(hR('cache-control')),
    timingAllowOrigin:    hR('timing-allow-origin') === '*',
    // HTTP/2 & HTTP/3 — detected via alt-svc or response protocol
    hasAltSvcH3:          /h3/i.test(hR('alt-svc')),
    // NEL / Report-To are strong CDN indicators regardless of provider
    hasNel:               res.headers.has('nel'),
    hasReportTo:          res.headers.has('report-to'),
    // Server-Timing present — individual providers inspect specific metrics
    hasServerTiming:      st.length > 0,
    serverTimingRaw:      st,
    // Via header (generic CDN signal; providers parse specific values)
    viaHeader:            hR('via'),
    // X-Cache (generic; providers check for provider-specific values)
    xCacheHeader:         hR('x-cache'),
  };
}

// ── Concurrency-limited task pool ──────────────────────────────
// Runs `items` through `worker` with at most `limit` in flight at once.
// Plain Promise.allSettled over 50-100+ probes fires every request
// simultaneously, which adds noise (easily flagged as a burst by WAFs)
// and increases tail latency; this keeps a steady, bounded window instead.
async function runPooled(items, limit, worker) {
  let idx = 0;
  async function runNext() {
    while (idx < items.length) {
      const i = idx++;
      await worker(items[i], i);
    }
  }
  const workers = Array(Math.min(limit, items.length)).fill(0).map(runNext);
  await Promise.allSettled(workers);
}

// ── Main scan ─────────────────────────────────────────────────
async function performScan(domain, progress) {
  await rangesReady;
  const providers = self.CDN_PROVIDERS || [];
  const allSig    = Object.fromEntries(providers.map(p => {
    const s = p.freshSignals();
    s.dnsShortTtl     = false;
    s.dnsVeryShortTtl = false;
    return [p.id, s];
  }));
  let resolvedIPs = [];
  const isDirectIP = isIPLiteral(domain);

  // ── Phase 1: DNS/DoH + Cookies (parallel) ────────────────
  if (isDirectIP) {
    // Direct IP scan: skip DNS resolution, use the literal IP as the only target.
    resolvedIPs = [domain];
    progress({ pct: 8, activity: 'Direct IP target — skipping DNS…' });

    for (const p of providers) {
      if (p.ipConfig?.ipSignal && ipMatches(domain, p.ipConfig.v4, p.ipConfig.v6))
        allSig[p.id][p.ipConfig.ipSignal] = true;
    }
  } else {
  progress({ pct: 5, activity: 'DNS lookup (A/AAAA/CNAME/MX/NS/TXT)…' });

  await Promise.allSettled([

    // DNS: A, AAAA, CNAME, MX, NS, TXT
    doHLookup(domain).then(({ ips, cname, mxRecords, nsRecords, txtRecords, minTTL }) => {
      resolvedIPs = ips;

      // TTL thresholds: CDNs typically use ≤300s; very short (<60s) is strong
      const shortTtl     = minTTL !== null && minTTL < 300;
      const veryShortTtl = minTTL !== null && minTTL < 60;

      // IP range matching
      for (const ip of ips) {
        for (const p of providers) {
          if (p.ipConfig?.ipSignal && ipMatches(ip, p.ipConfig.v4, p.ipConfig.v6))
            allSig[p.id][p.ipConfig.ipSignal] = true;
        }
      }

      // CNAME pattern matching
      if (cname) {
        for (const p of providers)
          for (const { re, signal } of (p.cnamePatterns || []))
            if (re.test(cname)) allSig[p.id][signal] = true;
      }

      // MX pattern matching
      for (const mx of mxRecords)
        for (const p of providers)
          for (const { re, signal } of (p.mxPatterns || []))
            if (re.test(mx)) allSig[p.id][signal] = true;

      // NS pattern matching — vanity NS is a medium-confidence signal
      for (const nsHost of nsRecords) {
        for (const { re, signal, pid } of NS_PATTERNS) {
          if (re.test(nsHost) && allSig[pid] && signal in allSig[pid])
            allSig[pid][signal] = true;
        }
        // Per-provider nsPatterns hook (optional)
        for (const p of providers)
          for (const { re, signal } of (p.nsPatterns || []))
            if (re.test(nsHost)) allSig[p.id][signal] = true;
      }

      // TXT record matching (per-provider txtPatterns hook)
      for (const rec of txtRecords)
        for (const p of providers)
          for (const { re, signal } of (p.txtPatterns || []))
            if (re.test(rec)) allSig[p.id][signal] = true;

      // Stamp TTL signals on all providers
      for (const p of providers) {
        allSig[p.id].dnsShortTtl     = shortTtl;
        allSig[p.id].dnsVeryShortTtl = veryShortTtl;
      }
    }),

    // Cookie scan
    (async () => {
      try {
        // Domain-scoped cookies (Domain attribute set, e.g. ".example.com")
        // plus host-only cookies (no Domain attribute — exact host match only).
        const [domainScoped, hostOnly] = await Promise.all([
          chrome.cookies.getAll({ domain: `.${domain}` }),
          chrome.cookies.getAll({ domain })
        ]);
        const seen = new Set();
        const cookies = [];
        for (const c of [...domainScoped, ...hostOnly]) {
          const key = `${c.name}|${c.domain}|${c.path}`;
          if (!seen.has(key)) { seen.add(key); cookies.push(c); }
        }
        for (const p of providers)
          if (p.extractCookies) p.extractCookies(cookies, allSig[p.id]);
      } catch {}
    })()
  ]);
  }

  // ── Phase 2: HTTP header + body (apex + www, or bare IP) ──
  // We skip www if its final URL is the same as apex (dedup redirect)
  const targets = isDirectIP
    ? [`https://${domain}`, `http://${domain}`]
    : domain.startsWith('www.')
      ? [`https://${domain}`]
      : [`https://${domain}`, `https://www.${domain}`];
  const timings    = [];
  let   lastFinalUrl = null;

  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    progress({ pct: 18 + i * 14, activity: `Fetching ${url}…` });

    try {
      const t0  = performance.now();
      const res = await fetchT(url, {
        redirect: 'follow',
        cache: 'no-store',
        // Send a realistic browser-like Accept to avoid serving bot-deflection pages
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        }
      });
      timings.push(performance.now() - t0);

      // Dedup: skip if redirect chain leads to same final URL
      const finalUrl = res.url;
      if (finalUrl === lastFinalUrl) continue;
      lastFinalUrl = finalUrl;

      // Read body for 200, 403, 503; also 429 (rate-limit/challenge pages)
      let body = null;
      if ([200, 403, 429, 503].includes(res.status))
        body = await res.text().catch(() => null);

      // Common signals — extracted once and merged into every provider
      const common = extractCommonSignals(res);
      for (const p of providers) {
        Object.assign(allSig[p.id], common);
        try { p.extract(res, body, allSig[p.id]); }
        catch { /* provider extractor must not crash the shared pass */ }
      }
    } catch {}
  }

  // ── Phase 3: Provider-specific probes (bounded concurrency) ─
  const allProbes = providers.flatMap(p =>
    (p.probes || []).map(probe => ({ p, probe }))
  );
  progress({ pct: 48, activity: `Running ${allProbes.length} targeted probes…` });

  let done = 0;
  await runPooled(allProbes, PROBE_CONCURRENCY, async ({ p, probe }) => {
    try {
      const res = await fetchT(probe.url(domain), probe.opts || {}, PROBE_TIMEOUT_MS);
      if ((probe.validStatuses || [200]).includes(res.status))
        await probe.handler(res, allSig[p.id]);
    } catch {}
    done++;
    const pct = 48 + Math.round((done / Math.max(allProbes.length, 1)) * 36);
    progress({ pct: Math.min(pct, 84), activity: `Probing ${p.name}…` });
  });

  // ── Phase 4: Timing anomaly ───────────────────────────────
  // First-request latency spike relative to subsequent requests suggests
  // a challenge/JS-injection layer (common in Cloudflare, Imperva, DataDome)
  if (timings.length >= 2) {
    const first   = timings[0];
    const avgRest = timings.slice(1).reduce((a, b) => a + b, 0) / (timings.length - 1);
    const anomaly = first > avgRest * 1.8 && first > 300;
    if (anomaly) {
      for (const p of providers)
        if ('timingAnomaly' in allSig[p.id]) allSig[p.id].timingAnomaly = true;
    }
  }

  // ── Phase 4.5: IP cross-verification (PTR + RDAP) ────────
  // Independent evidence that doesn't rely on response headers, so it
  // corroborates (or contradicts) the header/cookie-based signals above.
  progress({ pct: 86, activity: `Cross-verifying ${resolvedIPs.length} IP(s) via PTR/RDAP…` });
  const ipEvidence = await buildIpEvidence(resolvedIPs, providers);
  for (const ip of resolvedIPs) {
    const ev = ipEvidence[ip];
    if (!ev) continue;
    for (const pid of ev.matchedProviders) {
      if (allSig[pid]) allSig[pid].ipEvidenceMatch = true;
    }
  }

  // ── Phase 5: Score ────────────────────────────────────────
  progress({ pct: 92, activity: `Scoring ${providers.length} providers…` });

  const results = {};
  for (const p of providers) {
    let verdict;
    try   { verdict = p.score(allSig[p.id]); }
    catch { verdict = { score: 0, label: 'Unlikely', detected: false }; }
    results[p.id] = { signals: allSig[p.id], verdict };
  }

  return {
    providers: results,
    resolvedIPs,
    ipEvidence,
    isDirectIP,
    scannedAt: new Date().toISOString()
  };
}

// ── Startup ───────────────────────────────────────────────────
// Scans must not start scoring IP-range signals until cached ranges (or a
// fresh fetch) have loaded, otherwise ipSignal matches are silently skipped
// for the first scan after the service worker/background script wakes up.
const rangesReady = loadCachedRanges().catch(() => {});

// ── Port listener (progress streaming) ───────────────────────
chrome.runtime.onConnect.addListener(port => {
  if (port.name !== 'scan') return;
  let dead = false;
  port.onDisconnect.addListener(() => { dead = true; });

  port.onMessage.addListener(async msg => {
    if (msg.action !== 'scan') return;
    const { domain, forceRefresh } = msg;

    if (!forceRefresh) {
      const cached = await getCached(domain);
      if (cached) {
        if (!dead) port.postMessage({ type: 'result', data: cached, cached: true });
        return;
      }
    }

    const emit = update => { if (!dead) port.postMessage({ type: 'progress', ...update }); };
    try {
      const result = await performScan(domain, emit);
      await setCached(domain, result);
      await addToHistory(domain, result);
      if (!dead) port.postMessage({ type: 'result', data: result, cached: false });
    } catch (err) {
      if (!dead) port.postMessage({ type: 'error', message: err.message || 'Unknown error' });
    }
  });
});

// ── Legacy one-shot (fallback) ────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.action === 'scan') {
    performScan(msg.domain, () => {})
      .then(async r => { await setCached(msg.domain, r); await addToHistory(msg.domain, r); return r; })
      .then(r  => sendResponse(r))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.action === 'getHistory') {
    getHistory().then(list => sendResponse({ history: list }));
    return true;
  }
  if (msg.action === 'clearHistory') {
    clearHistory().then(() => sendResponse({ ok: true }));
    return true;
  }
});
