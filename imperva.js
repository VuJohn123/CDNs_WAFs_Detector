// Imperva / Incapsula Provider  v7.3
// 2026 updates:
//  • reese84 is now the *primary* bot-management cookie (replaces ___utmvc as main signal)
//    ___utmvc still seen but increasingly rare on modern Imperva deployments (2025-2026)
//  • Imperva block pages: 200 OK with body "Powered By Incapsula" — status check alone insufficient
//  • X-Iinfo validation regex updated — format confirmed stable: N-N-N-N S:N:N:N:N ...
//  • incap_ses_ and visid_incap_ cookie prefixes remain primary passive identifiers
//  • reese84 script served from obscure path with ?d= query param — not detectable passively
//    but the cookie itself IS detectable via cookies API

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'imperva', name: 'Imperva', color: '#e84d1c', icon: '🛡',

  freshSignals: () => ({
    impervaCname: false,
    xIinfoValid: false, xIinfo: false, xCdnIncapsula: false,
    xPoweredByIncapsula: false, xCdnForward: false, xImforwards: false,
    impervaCsp: false,
    incapsulaResource: false,
    incapsulaJsLoader: false, incapsulaBlock: false,
    incapsulaErrorClass: false, impervaBody: false,
    // 2026: reese84 is now the primary bot-management cookie signal
    cookies: {
      visidIncap: false, incapSes: false, nlbi: false,
      reese84: false,    // Primary Gen-3 Bot Management (now dominant)
      utmvc: false       // Legacy fingerprinting (declining prevalence)
    },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: { iinfoHeader: null }
  }),

  extract(res, body, s) {
    const h  = n => (res.headers.get(n) || '').toLowerCase();
    const hR = n => res.headers.get(n) || '';

    // X-Iinfo: definitively Imperva — format: N-N-N-N S:N:N:N:N ...
    const iinfo = hR('x-iinfo');
    if (iinfo) {
      s.xIinfo = true;
      s.meta.iinfoHeader = iinfo;
      // Validate format: starts with digits-digits-digits-digits
      if (/^\d+-\d+-\d+-\d+\s/.test(iinfo)) s.xIinfoValid = true;
    }

    if (/incapsula/i.test(h('x-cdn')))                             s.xCdnIncapsula        = true;
    if (/incapsula/i.test(h('x-powered-by')))                     s.xPoweredByIncapsula  = true;
    if (res.headers.has('x-cdn-forward'))                          s.xCdnForward          = true;
    if (res.headers.has('x-imforwards'))                           s.xImforwards          = true;

    // CSP header mentioning incapsula.com
    const csp = hR('content-security-policy');
    if (/incapsula\.com/i.test(csp))                               s.impervaCsp           = true;

    if (!body) return;
    // _Incapsula_Resource in body — JS challenge delivery endpoint reference
    if (/_Incapsula_Resource/i.test(body))                         s.incapsulaJsLoader    = true;
    // "Powered by Incapsula" or "Powered By Imperva" — block page (may be 200 OK)
    if (/powered\s+by\s+incapsula|powered\s+by\s+imperva/i.test(body)) s.impervaBody      = true;
    // Imperva WAF block page with incident ID
    if (/incapsula incident id|imperva\s+waf/i.test(body))         s.incapsulaBlock       = true;
    if (/class=["']incapsula-error/i.test(body))                   s.incapsulaErrorClass  = true;
  },

  probes: [
    { url: d => `https://${d}/_Incapsula_Resource`,
      validStatuses: [200,302,400,403,404],
      handler: async (res, s) => {
        // The resource endpoint exists and responds (even 403) = strong Imperva signal
        s.incapsulaResource = true;
      }
    }
  ],

  cnamePatterns: [
    { re: /\.incapdns\.net$/,      signal: 'impervaCname' },
    { re: /\.impervadns\.net$/,    signal: 'impervaCname' },
    { re: /\.imperva\.com$/,       signal: 'impervaCname' },
    { re: /\.incapsula\.com$/,     signal: 'impervaCname' },
  ],
  ptrPatterns: [
    { re: /incapdns\.net$|imperva\.com$/, signal: 'impervaCname' },
  ],
  orgNames: ['imperva', 'incapsula'],

  extractCookies(cookies, s) {
    const names = cookies.map(c => c.name);
    s.cookies.visidIncap = names.some(n => /^visid_incap_/i.test(n));
    s.cookies.incapSes   = names.some(n => /^incap_ses_/i.test(n));
    s.cookies.nlbi       = names.some(n => /^nlbi_/i.test(n));
    // reese84 — Gen 3 bot management (now primary)
    s.cookies.reese84    = names.some(n => n === 'reese84');
    // ___utmvc — legacy fingerprinting cookie (declining)
    s.cookies.utmvc      = names.some(n => n === '___utmvc');
  },

  score(s) {
    let n = 0;
    // Definitive exclusive signals
    if (s.xIinfoValid)            n += 65; // Exclusively Imperva
    if (s.xIinfo)                 n += 50;
    if (s.impervaCname)           n += 52;
    if (s.cookies?.visidIncap)    n += 48;
    if (s.cookies?.incapSes)      n += 46;
    // reese84 is now the primary bot management signal (2026)
    if (s.cookies?.reese84)       n += 44;
    if (s.xCdnIncapsula)          n += 44;
    if (s.incapsulaBlock)         n += 40;
    if (s.incapsulaResource)      n += 38;
    if (s.cookies?.nlbi)          n += 36;
    if (s.impervaBody)            n += 35;
    if (s.incapsulaJsLoader)      n += 32;
    if (s.xPoweredByIncapsula)    n += 30;
    if (s.impervaCsp)             n += 28;
    if (s.incapsulaErrorClass)    n += 26;
    if (s.xCdnForward)            n += 18;
    if (s.xImforwards)            n += 14;
    // ___utmvc: still a corroborator but less reliable now
    if (s.cookies?.utmvc && n > 10) n += 10;
    if (s.timingAnomaly && n > 20) n += 12;
    if (s.dnsShortTtl && n >= 20)  n += 5;

    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed Imperva (Incapsula)';
    else if (n >= 55) label = 'Highly Likely Imperva';
    else if (n >= 35) label = 'Possible Imperva';
    return { score: n, label, detected: n >= 35 };
  }
});
