// Heroku Provider (new in v9.5.14)
// Confidence notes: same conservative approach as render.js/railway.js/
// denodeploy.js — Heroku's own router does add an X-Request-ID header
// (per devcenter.heroku.com/articles/http-request-id), but that header
// name is generic enough that many unrelated services also set it under
// the same name, so it isn't a reliable exclusive signal and isn't
// checked here. What IS reliable: the officially documented default
// domain pattern, *.herokuapp.com, confirmed directly from Heroku's own
// DevCenter docs (still actively maintained — Heroku, a Salesforce
// subsidiary, replatformed onto Kubernetes in 2024 and remains a live
// PaaS as of 2026, not a legacy/defunct product).

self.CDN_PROVIDERS = self.CDN_PROVIDERS || [];
self.CDN_PROVIDERS.push({
  id: 'heroku', name: 'Heroku', color: '#79589f', icon: '🟣',

  knownHeaders: [],
  productType: 'App/dyno hosting (not a traditional CDN)',

  freshSignals: () => ({
    herokuCname: false,
    dnsShortTtl: false, dnsVeryShortTtl: false, timingAnomaly: false,
    meta: {}
  }),

  extract() {
    // No exclusive header signal to check — see file header comment.
  },

  probes: [],

  cnamePatterns: [
    { re: /\.herokuapp\.com$/, signal: 'herokuCname' },
    { re: /\.herokudns\.com$/, signal: 'herokuCname' }, // Heroku's SNI/TLS custom-domain routing layer
  ],
  ptrPatterns: [],
  orgNames: ['heroku', 'salesforce'],
  mxPatterns: [],
  extractCookies() {},

  score(s) {
    let n = 0;
    if (s.herokuCname)        n = Math.max(n, 85); // documented official domain pattern
    if (s.ipEvidenceMatch)    n += 10;
    n = Math.min(n, 100);
    let label = 'Unlikely';
    if      (n >= 80) label = 'Likely Heroku';
    else if (n >= 45) label = 'Possible Heroku';
    else if (n >= 22) label = 'Weak Heroku Indicators';
    return { score: n, label, detected: n >= 22 };
  }
});
