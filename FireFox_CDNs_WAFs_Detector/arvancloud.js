// ArvanCloud CDN/WAF Provider  v7.5 (NEW)
// ============================================================
// ArvanCloud is a major Middle East / Iran-region CDN, DDoS protection,
// and WAF provider with 40+ PoPs and a documented Layer 7 DDoS
// challenge-cookie mechanism.
//
// Documented signals (ArvanCloud official docs):
//   CNAME → {hash}.cdn.arvancloud.{ir,com}, *.arvancloud.ir, *.arvancloud.com
//   DDoS Layer 7 protection sets a challenge cookie + redirect when enabled
//   Server / via headers are not strongly standardized publicly; rely
//   primarily on CNAME + cookie + block-page body signals.
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'arvancloud', name: 'ArvanCloud', color: '#ff5252', icon: '🛰',
  ipConfig: null,

  freshSignals: () => ({
    arvanCname: false,
    arvanChallengeBody: false, arvanWafBlock: false,
    cookies: { arvanDdos: false },
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    if (!body) return;
    if (/arvancloud/i.test(body) && /(ddos|protection|please wait|checking your browser)/i.test(body))
      s.arvanChallengeBody = true;
    if (/arvancloud.*(firewall|waf|blocked)/i.test(body)) s.arvanWafBlock = true;
  },

  probes: [],
  cnamePatterns: [
    { re: /\.cdn\.arvancloud\.ir$/,  signal: 'arvanCname' },
    { re: /\.cdn\.arvancloud\.com$/, signal: 'arvanCname' },
    { re: /\.arvancloud\.ir$/,       signal: 'arvanCname' },
    { re: /\.arvancloud\.com$/,      signal: 'arvanCname' },
  ],
  ptrPatterns: [
    { re: /arvancloud\.(ir|com)$/, signal: 'arvanCname' },
  ],
  orgNames: ['arvan cloud', 'arvancloud'],

  extractCookies(cookies, s) {
    // ArvanCloud's Layer 7 DDoS challenge cookie name is not publicly fixed/documented
    // as a single literal string; match common naming convention conservatively.
    s.cookies.arvanDdos = cookies.some(c => /^arvan[_-]?(ddos|challenge)/i.test(c.name));
  },

  score(s) {
    let n = 0;
    if (s.arvanCname)          n = Math.max(n, 90); // CNAME is the most reliable signal here
    if (s.arvanWafBlock)       n += 40;
    if (s.arvanChallengeBody)  n += 35;
    if (s.cookies?.arvanDdos)  n += 30;
    if (s.ipEvidenceMatch) n += 10; // Independent PTR/RDAP corroborator
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Confirmed ArvanCloud';
    else if (n >= 55) label = 'Highly Likely ArvanCloud';
    else if (n >= 30) label = 'Possible ArvanCloud';
    return { score: n, label, detected: n >= 30 };
  }
});
