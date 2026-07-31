// VNCDN / VNIS (VNETWORK) Provider  v7.5 (NEW)
// ============================================================
// VNCDN is VNETWORK's CDN product — the leading domestically-deployed
// CDN in Vietnam, integrated directly into Viettel/VNPT/FPT/MobiFone
// ISP infrastructure. VNIS is VNETWORK's umbrella security/WAAP brand.
//
// NOTE ON CONFIDENCE: Unlike the global providers above, VNETWORK does
// not publish a single authoritative spec page listing exact CNAME
// suffixes or header names for VNCDN (as of this research pass). The
// patterns below are conservative, low-to-medium-confidence signals
// based on the vendor's own domain/brand names. This detector is
// intentionally capped at a lower maximum confidence than the other
// providers until official header/CNAME documentation can be verified
// — avoid overstating certainty for a regional provider with sparse
// public technical documentation.
// ============================================================

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'vncdn', name: 'VNCDN (VNETWORK)', color: '#0072ce', icon: '🇻🇳',
  ipConfig: null,

  freshSignals: () => ({
    vncdnCname: false,
    vncdnHeaderRef: false, vnisBlockBody: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract(res, body, s) {
    const hR = n => res.headers.get(n) || '';
    // Conservative — only catches an explicit self-identifying header value if present
    if (/vncdn|vnetwork|vnis/i.test(hR('server')) || /vncdn|vnetwork/i.test(hR('via')))
      s.vncdnHeaderRef = true;

    if (!body) return;
    if (/vnis|vnetwork|vncdn/i.test(body) && /(blocked|protection|firewall|access denied)/i.test(body))
      s.vnisBlockBody = true;
  },

  probes: [],
  cnamePatterns: [
    { re: /\.vncdn\.net$/,    signal: 'vncdnCname' },
    { re: /\.vncdn\.cloud$/,  signal: 'vncdnCname' },
    { re: /\.vnetwork\.vn$/,  signal: 'vncdnCname' },
    { re: /\.vnis\.vn$/,      signal: 'vncdnCname' },
  ],
  ptrPatterns: [
    { re: /vncdn\.net$|vncdn\.cloud$|vnetwork\.vn$|vnis\.vn$/, signal: 'vncdnCname' },
  ],
  orgNames: ['vnetwork', 'vncdn'],

  extractCookies() {},

  score(s) {
    let n = 0;
    // Capped lower than global providers — patterns are vendor-name-based,
    // not independently verified against official technical documentation.
    if (s.vncdnCname)       n = Math.max(n, 70);
    if (s.vncdnHeaderRef)   n += 35;
    if (s.vnisBlockBody)    n += 30;
    n = Math.min(n, 90); // intentional cap — see note above
    // Independent PTR/RDAP evidence is real corroboration from a source this
    // detector doesn't otherwise have for VNCDN, so it's allowed to push past
    // the heuristic-only cap (but still short of "confirmed").
    if (s.ipEvidenceMatch) n = Math.min(Math.max(n, 70) + 10, 95);
    let label = 'Unlikely';
    if      (n >= 70) label = 'Likely VNCDN / VNIS (unverified header spec)';
    else if (n >= 40) label = 'Possible VNCDN / VNIS';
    return { score: n, label, detected: n >= 40 };
  }
});
