// Deno Deploy Provider (new in v9.5.12)
// Confidence notes: same conservative approach as Render.js — Deno Deploy's
// own infra-added response headers aren't documented publicly, so this
// leans almost entirely on the officially-documented default domain
// patterns rather than guessing at header names.
//
// Two domain families, both from Deno's own docs (docs.deno.com/deploy):
//  - "Classic" platform: preview URLs at $PROJECT_ID.deno.dev. Classic was
//    shut down July 20, 2026, but existing custom-domain sites that were
//    CNAME'd to a *.deno.dev target will keep resolving there for some
//    time yet, so it's still worth matching.
//  - Current platform: default org domain at your-org.deno.net.
// No knownHeaders declared — deliberately not guessing at a header name
// with no public documentation to back it up (see the "no bịa" project
// rule). If a real Deno-specific header surfaces later (crowd-reported or
// otherwise verified), it belongs here.

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'denodeploy', name: 'Deno Deploy', color: '#70ffaf', icon: '🦕',

  knownHeaders: [],
  productType: 'App/edge function hosting (not a traditional CDN)',

  freshSignals: () => ({
    denoCname: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract() {
    // No documented header signal to check — see file header comment.
  },

  probes: [],

  cnamePatterns: [
    { re: /\.deno\.dev$/, signal: 'denoCname' },
    { re: /\.deno\.net$/, signal: 'denoCname' },
  ],
  ptrPatterns: [],
  orgNames: ['deno', 'deno deploy', 'deno land'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.denoCname)          n = Math.max(n, 85); // documented official domain pattern
    if (s.ipEvidenceMatch)    n += 10;
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Likely Deno Deploy';
    else if (n >= 45) label = 'Possible Deno Deploy';
    else if (n >= 22) label = 'Weak Deno Deploy Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
