// ============================================================
// Multi-CDN/WAF Detector — popup.js  v7.1
// Bug fixes from v6:
//   • Vercel color changed to #e2e8f0 (visible on dark bg)
//   • Full null-guard on pv?.verdict?.label ?? 'Unlikely'
//   • pc-bar hidden when score=0 (no spurious colored stub)
//   • Re-scan button bypasses 5-min cache
//   • DNS TTL displayed in Session Intel
//   • Multi-provider overlap warning
//   • 12-provider grid (3-col) with correct layout
// ============================================================

const PROVIDER_UI = {
  cloudflare: { name:'Cloudflare', color:'#f38020', icon:'⛅', groups:[
    { title:'Network', signals:[
      {key:'cfIP',               label:'Resolves to CF IP',                tip:'A/AAAA in Cloudflare IP ranges'},
      {key:'cfCname',            label:'CNAME → cdn.cloudflare.net'},
      {key:'cfPages',            label:'CNAME → *.pages.dev',              tip:'Cloudflare Pages hosting'},
      {key:'cfEmailMx',          label:'MX → mx.cloudflare.net',           tip:'CF Email Routing'},
    ]},
    { title:'Identity Headers', signals:[
      {key:'cfRay',              label:'CF-RAY present'},
      {key:'cfRayValid',         label:'CF-RAY valid {16hex}-{IATA}'},
      {key:'serverHeader',       label:'Server: cloudflare'},
      {key:'cdnLoop',            label:'CDN-Loop: cloudflare',              tip:'Loop-prevention header — proves CF edge'},
      {key:'cfEwVia',            label:'CF-EW-Via (Workers active)'},
      {key:'cfVisitor',          label:'CF-Visitor (proxy JSON)'},
      {key:'cfEdgeCache',        label:'CF-Edge-Cache (Enterprise)'},
      {key:'cfTrueClientIp',     label:'True-Client-IP / CF-Connecting-IP'},
      {key:'cfPagesHeaders',     label:'CF-Pages-Commit-SHA / Deployment-ID'},
      {key:'cfBgj',              label:'CF-BGJ (Enterprise internal)'},
      {key:'cfRequestId',        label:'CF-Request-ID (supplementary trace ID)'},
    ]},
    { title:'Cache / WAF / H3', signals:[
      {key:'cfCacheValid',       label:'CF-Cache-Status valid value'},
      {key:'cfMitigated',        label:'CF-Mitigated: challenge'},
      {key:'nelCloudflare',      label:'Report-To: nel.cloudflare.com'},
      {key:'h3AltSvc',           label:'Alt-Svc: h3=\":443\" (CF format)'},
    ]},
    { title:'cdn-cgi Probes', signals:[
      {key:'trace',              label:'/cdn-cgi/trace reachable'},
      {key:'traceConfirmed',     label:'Trace colo= confirmed',             tip:'Proves live CF edge proxying'},
      {key:'assets',             label:'/cdn-cgi/challenge-platform'},
      {key:'cfRum',              label:'/cdn-cgi/rum (RUM beacon)'},
      {key:'cfZaraz',            label:'/cdn-cgi/zaraz (Zaraz tag mgr)'},
      {key:'cfImageResizing',    label:'/cdn-cgi/image (Image Resizing)'},
      {key:'cfBotManagement',    label:'/cdn-cgi/bot-management probe'},
    ]},
    { title:'Trace Intel', signals:[
      {key:'traceKex',           label:'Post-Quantum KEX (MLKEM768)'},
      {key:'traceGateway',       label:'Zero Trust Gateway (gateway=on)'},
      {key:'traceWarp',          label:'WARP VPN (warp=on)'},
      {key:'traceRbi',           label:'Remote Browser Isolation (rbi=on)'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'challengePage',      label:'Challenge / 5-second screen'},
      {key:'turnstile',          label:'Turnstile / JS Challenge'},
      {key:'aiLabyrinth',        label:'AI Labyrinth honeypot',             tip:'_cf_chl_opt injection'},
      {key:'cfCvParams',         label:'window.__CF$cv$params in body'},
      {key:'cfRocketLoader',     label:'Rocket Loader (/cdn-cgi/scripts/)'},
      {key:'cfEmailObfuscation', label:'Email Obfuscation (data-cfemail)'},
      {key:'cfErrorCode',        label:'CF error code 1xxx in body'},
    ]},
    { title:'Cookies', signals:[
      {key:'cookies.cfClearance',label:'cf_clearance',                      tip:'Issued after passing a challenge'},
      {key:'cookies.cfBm',       label:'__cf_bm (Bot Management)'},
      {key:'cookies.cfWaiting',  label:'__cfwaitingroom'},
      {key:'cookies.cfAccess',   label:'CF_Authorization (Zero Trust)'},
    ]},
  ]},

  google: { name:'Google', color:'#4285f4', icon:'🔵', groups:[
    { title:'Network', signals:[
      {key:'googleIP',            label:'Resolves to Google IP'},
      {key:'googleCname',         label:'CNAME → Google infrastructure'},
      {key:'googleFirebaseCname', label:'CNAME → Firebase (*.web.app)'},
      {key:'googleRunCname',      label:'CNAME → Cloud Run (*.run.app)'},
      {key:'googleWorkspaceMx',   label:'MX → Google Workspace'},
    ]},
    { title:'Via / Server', signals:[
      {key:'viaGoogleValid',      label:'Via: *.google.com (validated)',     tip:'Strongest single GFE signal'},
      {key:'viaGoogle',           label:'Via: 1.1 google (generic)'},
      {key:'serverGws',           label:'Server: gws (Google Web Server)'},
      {key:'serverEsf',           label:'Server: ESF (Endpoints ServiceFront)'},
      {key:'serverGse',           label:'Server: GSE (App Engine)'},
      {key:'serverUploadServer',  label:'Server: UploadServer (Cloud Storage)'},
      {key:'googleH3',            label:'Alt-Svc ma=2592000 (Google H3)'},
    ]},
    { title:'Tracing / Internal Headers', signals:[
      {key:'xCloudTraceValid',    label:'X-Cloud-Trace-Context (validated)'},
      {key:'xCloudTrace',         label:'X-Cloud-Trace-Context present'},
      {key:'xGoogBackends',       label:'X-Google-Backends / X-GFE headers'},
      {key:'xGfeStage',           label:'X-GFE-Request-Stage'},
      {key:'xAppEngine',          label:'X-AppEngine-Country/City'},
      {key:'xGoogStoredContent',  label:'X-Goog-Stored-Content (GCS)'},
      {key:'xGoogHash',           label:'X-Goog-Hash (GCS content hash)'},
      {key:'xGoogExpiration',     label:'X-Goog-Expiration (signed URL)'},
      {key:'xGuploader',          label:'X-GUploader-UploadId (GCS)'},
      {key:'xFirebase',           label:'X-Firebase-* headers'},
    ]},
    { title:'WAF / Content', signals:[
      {key:'cloudArmorBlock',     label:'Cloud Armor WAF block page'},
      {key:'googleErrorPage',     label:'Google GFE error page'},
    ]},
  ]},

  akamai: { name:'Akamai', color:'#009bde', icon:'🌊', groups:[
    { title:'Network', signals:[
      {key:'akamaiCname',        label:'CNAME → Akamai',                   tip:'*.akamaiedge.net, *.edgekey.net…'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverAkamai',        label:'Server: AkamaiGHost / NetStorage', tip:'Exclusively Akamai'},
      {key:'xAkamaiTransformed',  label:'X-Akamai-Transformed'},
      {key:'xAkamaiRequestId',    label:'X-Akamai-Request-ID'},
      {key:'xAkamaiEdgescape',    label:'X-Akamai-Edgescape (geo data)'},
      {key:'xAkamaiOriginHop',    label:'Akamai-Origin-Hop'},
      {key:'xAkamaiGrn',          label:'Akamai-GRN (Ghost Request #)'},
      {key:'xAkamaiCacheStatus',  label:'Akamai-Cache-Status'},
      {key:'xAkamaiSslSid',       label:'X-Akamai-SSL-Client-Sid'},
      {key:'xAkamaiSessionInfo',  label:'X-Akamai-Session-Info (Bot Mgr)'},
      {key:'xTrueCacheKey',       label:'X-True-Cache-Key'},
      {key:'xSerial',             label:'X-Serial (edge serial #)'},
      {key:'xCacheAkamai',        label:'X-Cache: TCP_* from *.akamai.net'},
      {key:'xCheckCacheable',     label:'X-Check-Cacheable (pragma probe)'},
    ]},
    { title:'Active Probes', signals:[
      {key:'pragmaProbe',         label:'Pragma probe returned diagnostics'},
      {key:'akamaiSureRoute',     label:'/akamai/sureroute-test-object.html'},
      {key:'akamaiMpulse',        label:'/_mPulse/api/v1/ (Akamai RUM)'},
    ]},
    { title:'WAF / Content', signals:[
      {key:'akamaiWafBlock',      label:'Kona WAF block (Reference #)'},
      {key:'akamaiErrorBody',     label:'Akamai Error in body'},
    ]},
    { title:'Bot Manager Cookies', signals:[
      {key:'cookies.abck',        label:'_abck (Bot Manager sensor)'},
      {key:'cookies.bmSz',        label:'bm_sz (session size)'},
      {key:'cookies.akBmsc',      label:'ak_bmsc (session)'},
      {key:'cookies.bmSv',        label:'bm_sv (visitor)'},
      {key:'cookies.bmMi',        label:'bm_mi (machine info)'},
    ]},
  ]},

  fastly: { name:'Fastly', color:'#ff282d', icon:'⚡', groups:[
    { title:'Network', signals:[
      {key:'fastlyIP',            label:'Resolves to Fastly IP'},
      {key:'fastlyCname',         label:'CNAME → *.fastly.net'},
    ]},
    { title:'Fastly-Proprietary Headers', signals:[
      {key:'xServedByValid',      label:'X-Served-By (validated)',          tip:'cache-{city}{id}-{IATA} per Fastly docs'},
      {key:'xServedByShielded',   label:'X-Served-By: 2+ entries (shielded)'},
      {key:'xTimerValid',         label:'X-Timer (validated format)'},
      {key:'cdnLoopFastly',       label:'CDN-Loop: Fastly',                 tip:'Distinct from CDN-Loop: cloudflare'},
      {key:'fastlyRequestId',     label:'X-Fastly-Request-ID present'},
      {key:'fastlyRequestIdValid',label:'X-Fastly-Request-ID (validated 40-hex)', tip:'40 lowercase hex chars confirmed per 2026 Fastly docs'},
      {key:'fastlyImageOpto',     label:'X-Fastly-Imageopto-Api'},
      {key:'fastlyRestarts',      label:'Fastly-Restarts'},
      {key:'xCacheHits',          label:'X-Cache-Hits (per-hop count)'},
      {key:'xCacheMultiHit',      label:'X-Cache multi-value (shielded)'},
      {key:'surrogateControl',    label:'Surrogate-Control'},
    ]},
    { title:'Debug Probe (Fastly-Debug: 1)', signals:[
      {key:'fastlyDebugDigest',   label:'Fastly-Debug-Digest',              tip:'Only returned when Fastly-Debug: 1 sent'},
      {key:'fastlyDebugTtl',      label:'Fastly-Debug-TTL'},
      {key:'fastlyDebugPath',     label:'Fastly-Debug-Path'},
      {key:'fastlySurrogateKey',  label:'Surrogate-Key (debug-visible)'},
    ]},
    { title:'Varnish (lower confidence)', signals:[
      {key:'viaVarnish',          label:'Via: 1.1 varnish',                 tip:'Fastly uses Varnish; others do too'},
      {key:'serverVarnish',       label:'Server: Varnish'},
      {key:'xVarnish',            label:'X-Varnish (transaction ID)'},
    ]},
  ]},

  imperva: { name:'Imperva', color:'#e84d1c', icon:'🛡', groups:[
    { title:'Network', signals:[
      {key:'impervaCname',        label:'CNAME → Imperva',                  tip:'*.incapdns.net, *.impervadns.net'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xIinfoValid',         label:'X-Iinfo (validated)',              tip:'Exclusively Imperva — definitively identifies'},
      {key:'xIinfo',              label:'X-Iinfo present'},
      {key:'xCdnIncapsula',       label:'X-CDN: Incapsula'},
      {key:'xPoweredByIncapsula', label:'X-Powered-By: Incapsula'},
      {key:'xCdnForward',         label:'X-Cdn-Forward'},
      {key:'xImforwards',         label:'X-Imforwards'},
      {key:'impervaCsp',          label:'incapsula.com in CSP header'},
    ]},
    { title:'Active Probes', signals:[
      {key:'incapsulaResource',   label:'/_Incapsula_Resource reachable',   tip:'Imperva JS challenge delivery endpoint'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'incapsulaJsLoader',   label:'_Incapsula_Resource in body'},
      {key:'incapsulaBlock',      label:'Imperva WAF block page'},
      {key:'incapsulaErrorClass', label:'CSS class "incapsula-error"'},
      {key:'impervaBody',         label:'"Powered by Imperva" in body'},
    ]},
    { title:'Bot Management Cookies', signals:[
      {key:'cookies.visidIncap',  label:'visid_incap_{id}'},
      {key:'cookies.incapSes',    label:'incap_ses_{port}_{id}'},
      {key:'cookies.nlbi',        label:'nlbi_{id}'},
      {key:'cookies.reese84',     label:'reese84 (Gen 3 Bot Management)'},
      {key:'cookies.utmvc',       label:'___utmvc (fingerprinting)'},
    ]},
  ]},

  cloudfront: { name:'CloudFront', color:'#ff9900', icon:'☁', groups:[
    { title:'Network', signals:[
      {key:'cloudfrontIP',        label:'Resolves to CloudFront IP'},
      {key:'cloudfrontCname',     label:'CNAME → *.cloudfront.net'},
    ]},
    { title:'CloudFront-Exclusive Headers', signals:[
      {key:'xAmzCfIdValid',       label:'X-Amz-Cf-Id (validated)',          tip:'Exclusively CloudFront — no other CDN'},
      {key:'xAmzCfId',            label:'X-Amz-Cf-Id present'},
      {key:'xAmzCfPopValid',      label:'X-Amz-Cf-Pop (validated format)'},
      {key:'xAmzCfPop',           label:'X-Amz-Cf-Pop present'},
      {key:'viaCF',               label:'Via: 1.1 *.cloudfront.net'},
      {key:'serverCF',            label:'Server: CloudFront'},
      {key:'xCacheCF',            label:'X-Cache: Hit/Miss from cloudfront'},
    ]},
    { title:'AWS WAF / Lambda', signals:[
      {key:'xAmzWaf',             label:'X-Amzn-Waf-Action'},
      {key:'xAmzRequestId',       label:'X-Amzn-Requestid (Lambda@Edge)'},
      {key:'xAmzTraceId',         label:'X-Amzn-Trace-Id (X-Ray)'},
    ]},
    { title:'S3 Origin Headers', signals:[
      {key:'serverS3',            label:'Server: AmazonS3'},
      {key:'xAmzId2',             label:'X-Amz-Id-2'},
      {key:'xAmzBucketRegion',    label:'X-Amz-Bucket-Region'},
      {key:'xAmzVersionId',       label:'X-Amz-Version-Id'},
      {key:'xAmzStorageClass',    label:'X-Amz-Storage-Class'},
      {key:'xAmzDeleteMarker',    label:'X-Amz-Delete-Marker'},
      {key:'etagS3Format',        label:'ETag matches S3 MD5 format'},
    ]},
    { title:'Signed URL Cookies', signals:[
      {key:'cookies.cfPolicy',    label:'CloudFront-Policy'},
      {key:'cookies.cfSignature', label:'CloudFront-Signature'},
      {key:'cookies.cfKeyPair',   label:'CloudFront-Key-Pair-Id'},
    ]},
    { title:'Content', signals:[
      {key:'cloudfrontErrorPage', label:'CF error page ("Generated by cloudfront")'},
    ]},
  ]},

  azure: { name:'Azure', color:'#0078d4', icon:'🔷', groups:[
    { title:'Network', signals:[
      {key:'azureCname',          label:'CNAME → Azure CDN / Front Door',   tip:'*.azureedge.net, *.azurefd.net'},
      {key:'azureTrafficMgr',     label:'CNAME → *.trafficmanager.net'},
    ]},
    { title:'Front Door Headers', signals:[
      {key:'xAzureRefValid',      label:'X-Azure-Ref (validated)',           tip:'Both old base64 & new 2026 timestamp formats accepted'},
      {key:'xAzureRef',           label:'X-Azure-Ref present'},
      {key:'xAzureFdidValid',     label:'X-Azure-FDID (validated UUID)'},
      {key:'xAzureFdid',          label:'X-Azure-FDID present'},
      {key:'viaAzure',            label:'Via: 1.1 Azure'},
      {key:'xAzureRequestChain',  label:'X-Azure-RequestChain (loop detection)', tip:'hops={N} — confirmed in 2026 AFD docs'},
      {key:'xAzureCacheHit',      label:'X-Cache with AFD context'},
    ]},
    { title:'X-MS-* Headers', signals:[
      {key:'xMsRoutingName',      label:'X-MS-Routing-Name'},
      {key:'xMsRequestId',        label:'X-MS-Request-Id'},
      {key:'xMsVersion',          label:'X-MS-Version'},
      {key:'xMsClientRequestId',  label:'X-MS-Client-Request-Id'},
      {key:'xMsActivityId',       label:'X-MS-Activity-Id'},
      {key:'xMsEdge',             label:'X-MS-Edge-* family'},
    ]},
    { title:'Blob Storage Headers', signals:[
      {key:'serverAzureStorage',  label:'Server: Windows-Azure-Blob/Table'},
      {key:'xMsBlobType',         label:'X-MS-Blob-Type'},
      {key:'xMsAccessTier',       label:'X-MS-Access-Tier (Hot/Cool/Archive)'},
      {key:'xMsServerEncrypted',  label:'X-MS-Server-Encrypted: true'},
      {key:'xMsCreationTime',     label:'X-MS-Creation-Time'},
    ]},
    { title:'Probe / WAF / Content', signals:[
      {key:'azureDebugHeaders',   label:'X-Azure-DebugInfo probe responded'},
      {key:'serverIIS',           label:'Server: Microsoft-IIS'},
      {key:'azureWafBlock',       label:'Azure WAF block page'},
      {key:'azureErrorPage',      label:'Azure error page body'},
    ]},
  ]},

  sucuri: { name:'Sucuri', color:'#e77b30', icon:'🔒', groups:[
    { title:'Network', signals:[
      {key:'sucuriCname',         label:'CNAME → Sucuri',                   tip:'*.sucuri.net, *.cloudproxy.sucuri.net'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xSucuriIdValid',      label:'X-Sucuri-ID (validated)',           tip:'Definitively Sucuri — numeric request ID'},
      {key:'xSucuriId',           label:'X-Sucuri-ID present'},
      {key:'xSucuriCacheValid',   label:'X-Sucuri-Cache (valid value)'},
      {key:'xSucuriCache',        label:'X-Sucuri-Cache present'},
      {key:'xSucuriVersion',      label:'X-Sucuri-Version'},
      {key:'xSucuriGeneratedTime',label:'X-Sucuri-Generated-Time'},
      {key:'serverCloudProxy',    label:'Server: cloudproxy'},
    ]},
    { title:'Content Analysis', signals:[
      {key:'sucuriBlockPage',     label:'Sucuri WAF block page body'},
      {key:'sucuriJsChallenge',   label:'Sucuri JS browser verification'},
      {key:'sucuriAccessDenied',  label:'"Access Denied" from Sucuri'},
      {key:'sucuriCsrf',          label:'Sucuri CSRF protection page'},
    ]},
  ]},

  // Vercel color: #e2e8f0 (light slate — visible on dark bg, matches Vercel dark-mode branding)
  // v6 used #000000 which was invisible against the dark popup background
  vercel: { name:'Vercel', color:'#e2e8f0', icon:'▲', groups:[
    { title:'Network', signals:[
      {key:'vercelCname',         label:'CNAME → Vercel',                   tip:'*.vercel.app, *.vercel-dns.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xVercelIdValid',      label:'X-Vercel-ID (validated)',           tip:'2026 format: {region}::[{region}::]{node}-{ts_ms}-{hex} — multi-region allowed'},
      {key:'xVercelId',           label:'X-Vercel-ID present'},
      {key:'xVercelCacheValid',   label:'X-Vercel-Cache (valid value)'},
      {key:'xVercelCache',        label:'X-Vercel-Cache present'},
      {key:'serverVercel',        label:'Server: Vercel'},
      {key:'xMatchedPath',        label:'X-Matched-Path (routing)',          tip:'Exclusive to Vercel routing internals'},
      {key:'xDeploymentId',       label:'X-Deployment-ID'},
      {key:'xVercelSk',           label:'X-Vercel-SK (Skew Protection)'},
    ]},
    { title:'Next.js / Edge Functions', signals:[
      {key:'xNextjsPrerender',    label:'X-Nextjs-Prerender (ISR)'},
      {key:'xNextjsStaleTime',    label:'X-Nextjs-Stale-Time'},
      {key:'xNextCacheTags',      label:'X-Next-Cache-Tags'},
      {key:'xNextjsCache',        label:'X-Nextjs-Cache'},
      {key:'xMiddlewareRewrite',  label:'X-Middleware-Rewrite'},
      {key:'xMiddlewareInvoke',   label:'X-Middleware-Invoke'},
      {key:'xVercelError',        label:'X-Vercel-Error'},
      {key:'xVercelExecRegion',   label:'X-Vercel-Execution-Region'},
    ]},
  ]},

  netlify: { name:'Netlify', color:'#00c7b7', icon:'💠', groups:[
    { title:'Network', signals:[
      {key:'netlifyCname',        label:'CNAME → Netlify',                  tip:'*.netlify.app, *.netlify.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xNfRequestIdValid',   label:'X-NF-Request-ID (validated ULID)',  tip:'Exactly 26-char Crockford Base32 ULID — confirmed per Netlify docs July 2025'},
      {key:'xNfRequestId',        label:'X-NF-Request-ID present'},
      {key:'serverNetlify',       label:'Server: Netlify'},
      {key:'xNfEdgeCacheValid',   label:'X-NF-Edge-Cache (valid value)'},
      {key:'xNfEdgeCache',        label:'X-NF-Edge-Cache present'},
      {key:'xNfOriginCache',      label:'X-NF-Origin-Cache'},
      {key:'xNfPop',              label:'X-NF-Pop (edge PoP location)'},
      {key:'netlifyVary',         label:'Netlify-Vary (cache variation)'},
      {key:'xNetlifyOriginalPath',label:'X-Netlify-Original-Path'},
      {key:'xNetlifyRewrite',     label:'X-Netlify-Rewrite'},
      {key:'netlifyServerTiming', label:'Netlify-Server-Timing'},
      {key:'xNetlifyCache',       label:'X-Netlify-Cache'},
    ]},
    { title:'Content', signals:[
      {key:'netlifyErrorPage',    label:'Netlify error page body'},
    ]},
  ]},

  bunnycdn: { name:'BunnyCDN', color:'#f5a623', icon:'🐰', groups:[
    { title:'Network', signals:[
      {key:'bunnyIP',             label:'Resolves to BunnyCDN IP'},
      {key:'bunnyCname',          label:'CNAME → bunny.net',               tip:'*.b-cdn.net, *.bunnycdn.com'},
    ]},
    { title:'Server Header', signals:[
      {key:'serverBunnyValid',    label:'Server: BunnyCDN-{loc}-{id} (validated)', tip:'Definitively BunnyCDN per docs'},
      {key:'serverBunny',         label:'Server: BunnyCDN-* present'},
      {key:'viaBunny',            label:'Via: BunnyCDN'},
    ]},
    { title:'CDN-* Header Family', signals:[
      {key:'cdnRequestIdValid',   label:'CDN-RequestId (valid 32-hex)',     tip:'Documented BunnyCDN request tracking ID'},
      {key:'cdnRequestId',        label:'CDN-RequestId present'},
      {key:'cdnUid',              label:'CDN-UID (account UUID)'},
      {key:'cdnCacheValid',       label:'CDN-Cache (HIT/MISS/BYPASS)'},
      {key:'cdnCache',            label:'CDN-Cache present'},
      {key:'cdnPullzone',         label:'CDN-PullZone (numeric ID)'},
      {key:'cdnCachedAt',         label:'CDN-CachedAt (cache timestamp)'},
      {key:'cdnProxyVer',         label:'CDN-ProxyVer (proxy version)'},
      {key:'cdnRequestPullSuccess',label:'CDN-RequestPullSuccess: True'},
      {key:'cdnEdgeStorageId',    label:'CDN-EdgeStorageId'},
      {key:'cdnRequestCountryCode',label:'CDN-RequestCountryCode'},
    ]},
  ]},

  stackpath: { name:'StackPath', color:'#2196f3', icon:'⚙', groups:[
    { title:'Network', signals:[
      {key:'stackpathCname',      label:'CNAME → StackPath / EdgeCast',    tip:'*.hwcdn.net, *.stackpathcdn.com…'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverEcacc',         label:'Server: ECAcc (EdgeCast Accelerator)', tip:'Exclusively EdgeCast/StackPath'},
      {key:'serverEcs',           label:'Server: ECS (EdgeCast Server)'},
      {key:'xCacheHwcdnValid',    label:'X-Cache: HIT from *.hwcdn.net',   tip:'hwcdn.net FQDN proves StackPath'},
      {key:'xCacheHwcdn',         label:'X-Cache includes hwcdn.net'},
      {key:'xSpUid',              label:'X-SP-UID (StackPath unique ID)'},
      {key:'xEcCustomError',      label:'X-EC-Custom-Error: 1 (EdgeCast)'},
      {key:'xPullZone',           label:'X-Pull-Zone'},
      {key:'xSpEdge',             label:'X-SP-* header family'},
      {key:'xCacheHits',          label:'X-Cache-Hits'},
      {key:'xCacheAge',           label:'X-Cache-Age (seconds)'},
    ]},
    { title:'Content', signals:[
      {key:'ecErrorBody',         label:'EdgeCast / StackPath error page'},
    ]},
  ]},

  keycdn: { name:'KeyCDN', color:'#2a99ff', icon:'🔑', groups:[
    { title:'Network', signals:[
      {key:'keyCname',            label:'CNAME → KeyCDN',                  tip:'*.kxcdn.com, *.keycdn.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverKeycdn',        label:'Server: keycdn-engine',           tip:'Exclusively KeyCDN per published docs'},
      {key:'xEdgeLocation',       label:'X-Edge-Location (PoP name)'},
      {key:'xEdgeIp',             label:'X-Edge-Ip (edge server IP)'},
      {key:'xUniqueId',           label:'X-Unique-Id (per-request ID)'},
      {key:'xCacheKeycdn',        label:'X-Cache HIT/MISS (KeyCDN context)'},
      {key:'xPullZone',           label:'X-Pull-Zone (pull config ID)'},
      {key:'xCacheHits',          label:'X-Cache-Hits (cumulative count)'},
    ]},
    { title:'Content', signals:[
      {key:'keyCdnErrorPage',     label:'KeyCDN error page body'},
    ]},
  ]},

  gcore: { name:'Gcore', color:'#f04e23', icon:'🌐', groups:[
    { title:'Network', signals:[
      {key:'gcoreCname',          label:'CNAME → Gcore',                   tip:'*.gcdn.co, *.gc.onl, *.gcorelabs.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverGcore',         label:'Server: Gcore'},
      {key:'xIdValid',            label:'X-ID: ed-{a}-{b}-{c}-{d} (validated)',  tip:'Gcore encodes edge IP in X-ID'},
      {key:'xId',                 label:'X-ID present'},
      {key:'xCachedSince',        label:'X-Cached-Since (cache timestamp)', tip:'ISO datetime of edge cache population'},
      {key:'xCacheGcore',         label:'X-Cache HIT/MISS (Gcore context)'},
      {key:'gcorePop',            label:'X-Gcore-Pop (edge PoP)'},
      {key:'gShield',             label:'G-Shield (DDoS protection layer)'},
    ]},
    { title:'Content', signals:[
      {key:'gcoreErrorPage',      label:'Gcore error page body'},
    ]},
  ]},

  datadome: { name:'DataDome', color:'#7c3aed', icon:'🤖', productType:'Bot Protection (WAAP)', groups:[
    { title:'Cookies', signals:[
      {key:'cookies.datadome',       label:'datadome clearance cookie'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xDataDomeValid',         label:'X-DataDome: protected'},
      {key:'xDataDome',              label:'X-DataDome present'},
      {key:'xDataDomeBotHeaders',    label:'X-DataDome-Bot* headers (block response)'},
      {key:'xDdB',                   label:'X-DD-B backend signal'},
    ]},
    { title:'Content', signals:[
      {key:'captchaDeliveryRef',     label:'captcha-delivery.com reference', tip:'DataDome challenge delivery domain'},
      {key:'ddJsChallenge',          label:'DataDome JS challenge markers'},
      {key:'ddBlockBody',            label:'DataDome block page body'},
    ]},
  ]},

  perimeterx: { name:'PerimeterX', color:'#ff5a5f', icon:'🧩', productType:'Bot Protection (HUMAN Security)', groups:[
    { title:'Cookies', signals:[
      {key:'cookies.px3',            label:'_px3 Security Token cookie'},
      {key:'cookies.pxvid',          label:'_pxvid visitor ID cookie'},
      {key:'cookies.pxhd',           label:'_pxhd session cookie'},
      {key:'cookies.pxcts',          label:'_pxcts cookie'},
      {key:'cookies.px2',            label:'_px2 cookie'},
      {key:'cookies.px',             label:'_px cookie'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xPxAuthorization',       label:'X-PX-Authorization present'},
    ]},
    { title:'Content', signals:[
      {key:'pxCollectorRef',         label:'collector-*.perimeterx.net / px-cloud.net ref'},
      {key:'pxCdnRef',               label:'*.px-cdn.net reference'},
      {key:'pxPressHoldChallenge',   label:'"Press & Hold" challenge widget'},
      {key:'pxScriptRef',            label:'px.js / pxConfig script reference'},
      {key:'humanSecurityRef',       label:'HUMAN Security brand reference'},
    ]},
  ]},

  f5xc: { name:'F5 Distributed Cloud', color:'#e4002b', icon:'🟥', productType:'CDN + WAAP Hybrid', groups:[
    { title:'Network', signals:[
      {key:'serverVoltCdn',          label:'CNAME → F5 XC (volterra.io / ves.io)'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverVoltCdn',          label:'Server: volt-cdn',               tip:'Exclusive to F5 XC CDN Load Balancer'},
      {key:'xVolterraHeader',        label:'X-Volterra-* header family'},
      {key:'xCacheStatusF5',         label:'X-Cache-Status (F5 XC context)'},
      {key:'xRequestIdF5',           label:'X-Request-ID (F5 XC context)'},
    ]},
    { title:'Content', signals:[
      {key:'f5BotDefenseRef',        label:'F5/Shape/Volterra brand reference'},
      {key:'f5ShapeChallenge',       label:'Shape Security block page'},
    ]},
  ]},

  tencenteo: { name:'Tencent EdgeOne', color:'#00a4ff', icon:'🐧', groups:[
    { title:'Network', signals:[
      {key:'tencentCname',           label:'CNAME → Tencent EdgeOne',        tip:'*.qcloud.com, *.edgeone.app'},
    ]},
    { title:'Response Headers', signals:[
      {key:'serverTencentEo',        label:'Server: TencentEdgeOne'},
      {key:'cdnLoopTencent',         label:'CDN-Loop: tencent'},
      {key:'eoCacheStatusValid',     label:'EO-Cache-Status valid value'},
      {key:'eoCacheStatus',          label:'EO-Cache-Status present'},
      {key:'eoLogUuid',              label:'EO-LOG-UUID (request identifier)'},
      {key:'eoConnectingIp',         label:'EO-Connecting-IP'},
      {key:'eoClientDevice',         label:'EO-Client-Device'},
    ]},
  ]},

  alicdn: { name:'Alibaba Cloud CDN', color:'#ff6a00', icon:'🅰', groups:[
    { title:'Network', signals:[
      {key:'aliCname',               label:'CNAME → Alibaba Cloud CDN',      tip:'*.kunlunar.com, *.alicdn.com'},
    ]},
    { title:'Response Headers', signals:[
      {key:'xSwiftSaveTime',         label:'X-Swift-SaveTime',               tip:'Exclusive to Alibaba Cloud Swift cache layer'},
      {key:'xSwiftCacheTime',        label:'X-Swift-CacheTime'},
      {key:'xCacheSwift',            label:'X-Cache HIT/MISS (Swift context)'},
      {key:'ageHeader',              label:'Age header present (weak corroborator)'},
    ]},
  ]},

  arvancloud: { name:'ArvanCloud', color:'#ff5252', icon:'🛰', groups:[
    { title:'Network', signals:[
      {key:'arvanCname',             label:'CNAME → ArvanCloud',             tip:'*.cdn.arvancloud.ir / .com'},
    ]},
    { title:'Content', signals:[
      {key:'arvanWafBlock',          label:'ArvanCloud WAF block page'},
      {key:'arvanChallengeBody',     label:'ArvanCloud DDoS challenge page'},
    ]},
    { title:'Cookies', signals:[
      {key:'cookies.arvanDdos',      label:'ArvanCloud DDoS challenge cookie (heuristic name match)'},
    ]},
  ]},

  vncdn: { name:'VNCDN (VNETWORK)', color:'#0072ce', icon:'🇻🇳', productType:'CDN (heuristic, low public docs)', groups:[
    { title:'Network', signals:[
      {key:'vncdnCname',             label:'CNAME → VNCDN / VNIS',           tip:'*.vncdn.net, *.vncdn.cloud, *.vnetwork.vn — unverified spec, lower confidence'},
    ]},
    { title:'Response Headers', signals:[
      {key:'vncdnHeaderRef',         label:'Server/Via mentions VNCDN/VNETWORK'},
    ]},
    { title:'Content', signals:[
      {key:'vnisBlockBody',          label:'VNIS/VNETWORK protection page body'},
    ]},
  ]},
};


// ── CF PoP city lookup ────────────────────────────────────────
const CF_POPS = {
  ATL:'Atlanta',BOS:'Boston',CMH:'Columbus',DEN:'Denver',DFW:'Dallas',
  DTW:'Detroit',EWR:'Newark',HNL:'Honolulu',IAD:'Ashburn',IAH:'Houston',
  LAX:'Los Angeles',MCI:'Kansas City',MCO:'Orlando',MIA:'Miami',
  MSP:'Minneapolis',ORD:'Chicago',PDX:'Portland',PHX:'Phoenix',
  SEA:'Seattle',SFO:'San Francisco',SJC:'San Jose',TPA:'Tampa',
  YTO:'Toronto',YUL:'Montreal',YVR:'Vancouver',
  AMS:'Amsterdam',ARN:'Stockholm',ATH:'Athens',BCN:'Barcelona',
  BRU:'Brussels',BUD:'Budapest',CDG:'Paris',CPH:'Copenhagen',
  DUB:'Dublin',DUS:'Düsseldorf',FRA:'Frankfurt',GVA:'Geneva',
  HAM:'Hamburg',HEL:'Helsinki',LHR:'London',LIS:'Lisbon',
  MAD:'Madrid',MAN:'Manchester',MXP:'Milan',OSL:'Oslo',
  OTP:'Bucharest',PRG:'Prague',VIE:'Vienna',WAW:'Warsaw',ZRH:'Zurich',
  BKK:'Bangkok',BLR:'Bangalore',BOM:'Mumbai',DEL:'Delhi',
  HAN:'Hanoi',HKG:'Hong Kong',ICN:'Seoul',KIX:'Osaka',
  KUL:'Kuala Lumpur',MNL:'Manila',NRT:'Tokyo',SGN:'Ho Chi Minh City',
  SIN:'Singapore',SYD:'Sydney',TPE:'Taipei',DXB:'Dubai',
  DOH:'Doha',TLV:'Tel Aviv',GRU:'São Paulo',SCL:'Santiago',
};
function formatPoP(iata) {
  if (!iata) return null;
  const c = CF_POPS[iata.toUpperCase()];
  return c ? `${iata} — ${c}` : iata;
}

// ── DOM refs ──────────────────────────────────────────────────
const scanBtn     = document.getElementById('scan');
const rescanBtn   = document.getElementById('rescan');
const statusTextEl = document.getElementById('status-text');
const cachedBadgeEl = document.getElementById('cached-badge');
const domainInput = document.getElementById('domain');
const resultsEl   = document.getElementById('results');
const progressEl  = document.getElementById('progress');
const pctEl       = document.getElementById('pct');
const barEl       = document.getElementById('pbar');
const activityEl  = document.getElementById('activity');
const historyBtn  = document.getElementById('history');

// ── Auto-fill current tab hostname ────────────────────────────
try {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const url = tabs[0]?.url;
    if (url && /^https?:/.test(url)) domainInput.value = new URL(url).hostname;
  });
} catch {}

// ── Validation ────────────────────────────────────────────────
function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => +o >= 0 && +o <= 255);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
}
function isValidDomain(d) {
  if (isIPv4(d) || isIPv6(d)) return true;
  return d.length > 1 && d.length < 256 && /^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/i.test(d);
}

// ── Signal resolver — supports "cookies.cfBm" dot notation ───
function getSig(signals, key) {
  return key.split('.').reduce((o, k) => o?.[k], signals) ?? false;
}

// ── Status helpers ────────────────────────────────────────────
function setStatus(text, mod) {
  statusTextEl.className = mod === 'scanning' ? 'status-scan'
    : mod === 'detected' ? 'status-ok'
    : mod === 'not-detected' ? 'status-fail'
    : 'status-idle';
  statusTextEl.textContent = text;
  cachedBadgeEl.hidden = true;
}

// ── Progress UI ───────────────────────────────────────────────
function showProgress(show) {
  progressEl.hidden = !show;
  if (show) {
    barEl.classList.add('scanning');
  } else {
    barEl.classList.remove('scanning');
  }
}
function updateProgress(pct, activity) {
  if (pct > 0) barEl.classList.remove('scanning');
  pctEl.textContent     = `${pct}%`;
  barEl.style.width     = `${Math.min(pct, 100)}%`;
  activityEl.textContent = activity;
}

// ── Row renderers ─────────────────────────────────────────────
function boolRow(label, value, tip) {
  const t = tip ? ` title="${tip}"` : '';
  return `<div class="result-row ${value ? 'hit' : 'miss'}"${t}>
    <span>${label}</span><strong>${value ? '✔' : '✖'}</strong>
  </div>`;
}
function infoRow(label, value) {
  if (!value) return '';
  const safe = String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
  return `<div class="result-row info"><span>${label}</span><strong title="${safe}">${safe}</strong></div>`;
}
function sectionHdr(title) {
  return `<div class="section-header">${title}</div>`;
}

// ── Overview grid ─────────────────────────────────────────────
function renderOverview(result, cached) {
  if (!result?.providers) {
    resultsEl.innerHTML = '<div class="empty-state">No data to display.</div>';
    return;
  }

  const order    = Object.keys(PROVIDER_UI);
  const detected = order.filter(id => result.providers[id]?.verdict?.detected === true);

  let summary;
  if (detected.length === 0) {
    summary = 'No providers detected';
  } else {
    const names = detected.map(id => PROVIDER_UI[id]?.name || id).join(', ');
    summary = `${detected.length} provider${detected.length > 1 ? 's' : ''}: <strong>${names}</strong>`;
  }

  // Update status bar
  statusTextEl.className = detected.length > 0 ? 'status-ok' : 'status-fail';
  statusTextEl.innerHTML = detected.length > 0
    ? `${detected.length} provider${detected.length > 1 ? 's' : ''} detected — tap to inspect`
    : 'No providers detected';
  if (cached) {
    cachedBadgeEl.hidden = false;
  }

  const overlap = detected.length > 1
    ? `<div class="multi-warn">⚠ Multi-CDN/WAF deployment detected</div>` : '';
  const anycastNote = ipList.length > 1
    ? `<div class="anycast-note">${ipList.length} IPs resolved — tap an IP for cross-verification (PTR/RDAP)</div>` : '';

  const cards = order.map(id => {
    const ui    = PROVIDER_UI[id];
    if (!ui) return '';
    const pv    = result.providers?.[id];
    const score = pv?.verdict?.score   ?? 0;
    const label = pv?.verdict?.label   ?? 'Unlikely';
    const det   = pv?.verdict?.detected ?? false;

    return `
      <div class="provider-card ${det ? 'detected' : 'undetected'}"
           data-provider="${id}" style="--pc:${ui.color}">
        <div class="pc-head">
          <div class="pc-dot"></div>
          <span class="pc-name">${ui.name}</span>
          <span class="pc-score">${score}%</span>
        </div>
        <div class="pc-bar-wrap">
          ${score > 0 ? `<div class="pc-bar" style="width:${score}%"></div>` : ''}
        </div>
        <div class="pc-label">${label}</div>
      </div>`;
  }).join('');

  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const ipList = result.resolvedIPs || [];
  const ipsHtml = ipList.length
    ? `<div class="scan-ips">${ipList.map(ip => {
        const ev = result.ipEvidence?.[ip];
        const tag = ev?.org ? ` title="${escHtml(ev.org)}${ev.ptr ? ' · ' + escHtml(ev.ptr) : ''}"` : '';
        const verified = ev?.matchedProviders?.length ? ' ip-verified' : '';
        return `<span class="ip-chip${verified}" data-ip="${escHtml(ip)}"${tag}>${escHtml(ip)}</span>`;
      }).join('')}</div>` : '';

  const metaLine = `
    <div class="scan-meta">
      <span>${summary}</span>
      ${ipsHtml}
    </div>`;

  resultsEl.innerHTML = metaLine + overlap + anycastNote + `<div class="providers-grid">${cards}</div>`;

  resultsEl.querySelectorAll('.provider-card').forEach(card =>
    card.addEventListener('click', () => renderDetail(result, card.dataset.provider))
  );
  resultsEl.querySelectorAll('.ip-chip').forEach(chip =>
    chip.addEventListener('click', () => renderIpEvidence(result, chip.dataset.ip))
  );
}

// ── IP evidence detail (PTR / RDAP cross-verification) ────────
function renderIpEvidence(result, ip) {
  const ev = result.ipEvidence?.[ip];
  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  const rows = [];
  rows.push(infoRow('IP', ip));
  if (ev) {
    rows.push(infoRow('Reverse DNS (PTR)', ev.ptr || 'No PTR record'));
    rows.push(infoRow('Organization (RDAP)', ev.org || 'Unknown'));
    rows.push(infoRow('ASN Handle', ev.asnHandle));
    rows.push(infoRow('CIDR', ev.cidr));
    rows.push(infoRow('Country', ev.country));
    if (ev.matchedProviders?.length) {
      const names = ev.matchedProviders.map(id => PROVIDER_UI[id]?.name || id).join(', ');
      rows.push(`<div class="result-row hit"><span>Corroborates</span><strong>${escHtml(names)}</strong></div>`);
    } else {
      rows.push(`<div class="result-row miss"><span>Corroborates</span><strong>No provider match</strong></div>`);
    }
  } else {
    rows.push(`<div class="result-row miss"><span>Status</span><strong>No evidence gathered</strong></div>`);
  }

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">IP Evidence — ${escHtml(ip)}</span>
    </div>
    <div class="checks-list">
      ${sectionHdr('Cross-Verification (PTR + RDAP)')}
      ${rows.filter(Boolean).join('')}
    </div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    renderOverview(resultsEl._scan, resultsEl._cached);
  });
}

// ── Detail view ───────────────────────────────────────────────
// ── Session Intel field config — replaces the old per-provider if-chain.
// Each entry is a list of [label, getter(meta) => value|null] pairs.
// Adding a new provider's intel fields means adding one map entry here,
// not another `if (pid === ...)` branch in renderDetail.
const META_INTEL_CONFIG = {
  cloudflare: meta => [
    ['Data Center', formatPoP(meta.dataCenter)],
    ['CF-RAY ID',   meta.cfRayId],
    ['TLS',         meta.tlsVersion],
    ['HTTP',        meta.httpVersion],
    ['KEX',         meta.kex],
    ...(meta.warp    === 'on' ? [['WARP',    'Active']] : []),
    ...(meta.gateway === 'on' ? [['Gateway', 'Active']] : []),
    ...(meta.rbi     === 'on' ? [['RBI',     'Active']] : []),
    ['Flight ID',   meta.flightId],
  ],
  akamai: meta => [
    ['Edgescape',  (meta.edgescape || '').slice(0, 80)],
    ['Cache Node', (meta.cacheNode || '').slice(0, 60)],
  ],
  fastly: meta => [
    ['Cache Node',   meta.cacheNode],
    ['Shield Node',  meta.shieldNode],
    ['Edge Elapsed', meta.elapsedMs],
  ],
  imperva: meta => [
    ['X-Iinfo', (meta.iinfoHeader || '').slice(0, 80)],
  ],
  cloudfront: meta => [
    ['CF PoP',      meta.cfPop],
    ['Request ID', (meta.cfRequestId || '').slice(0, 55)],
  ],
  azure: meta => [
    ['Azure-Ref', (meta.azureRef || '').slice(0, 70)],
    ['FDID',       meta.fdid],
  ],
  sucuri: meta => [
    ['Sucuri ID', meta.sucuriId],
    ['Cache',     meta.cacheStatus],
  ],
  vercel: meta => [
    ['Vercel ID', (meta.vercelId || '').slice(0, 55)],
    ['Region',     meta.region],
    ['Deploy ID', (meta.deploymentId || '').slice(0, 45)],
  ],
  netlify: meta => [
    ['NF Request ID', meta.nfRequestId],
    ['Edge PoP',       meta.pop],
  ],
  google: meta => [
    ['Trace Context', (meta.traceContext || '').slice(0, 60)],
  ],
  bunnycdn: meta => [
    ['Server Node', meta.serverNode],
    ['Pull Zone',   meta.pullzone],
    ['Account UID', meta.uid],
    ['Request ID',  meta.requestId],
    ['Country',     meta.country],
  ],
  stackpath: meta => [
    ['Cache Node', (meta.cacheNode || '').slice(0, 60)],
    ['SP-UID',      meta.spUid],
  ],
  keycdn: meta => [
    ['Edge PoP',   meta.edgeLocation],
    ['Edge IP',    meta.edgeIp],
    ['Unique ID', (meta.uniqueId || '').slice(0, 55)],
  ],
  gcore: meta => [
    ['Server ID',    meta.serverId],
    ['Cached Since', meta.cachedSince],
    ['Edge PoP',     meta.pop],
  ],
};

function buildIntelRows(pid, signals) {
  const meta = signals.meta || {};
  const rows = [];

  const fields = META_INTEL_CONFIG[pid];
  if (fields) {
    for (const [label, value] of fields(meta)) rows.push(infoRow(label, value));
  }

  // Cross-cutting fields common to all providers
  if (signals.dnsVeryShortTtl)
    rows.push(infoRow('DNS TTL', '< 60s (very short — strong CDN indicator)'));
  else if (signals.dnsShortTtl)
    rows.push(infoRow('DNS TTL', '< 300s (CDN-typical short TTL)'));

  if (signals.ipEvidenceMatch)
    rows.push(infoRow('IP Cross-Verification', 'PTR/RDAP corroborates this provider'));

  return rows.filter(Boolean);
}

// ── Detail view ───────────────────────────────────────────────
function renderDetail(result, pid) {
  const ui = PROVIDER_UI[pid];
  const pv = result?.providers?.[pid];
  if (!ui || !pv) return;

  const signals = pv.signals || {};
  const verdict = pv.verdict  || { score: 0, label: 'Unlikely', detected: false };

  const groupsHtml = ui.groups.map(g =>
    sectionHdr(g.title) + g.signals.map(s =>
      boolRow(s.label, getSig(signals, s.key), s.tip || '')
    ).join('')
  ).join('');

  const metaHtml = buildIntelRows(pid, signals).join('');
  const intelSection = metaHtml ? sectionHdr('Session Intel') + metaHtml : '';

  const productTypeHtml = ui.productType
    ? `<div class="product-type-note">${ui.productType}</div>` : '';

  resultsEl.innerHTML = `
    <div class="detail-header" style="--pc:${ui.color}">
      <button class="back-btn" id="backBtn">← Back</button>
      <div class="detail-dot"></div>
      <span class="detail-name">${ui.name}</span>
      <span class="detail-score">${verdict.score}%</span>
    </div>
    ${productTypeHtml}
    <div class="detail-verdict ${verdict.detected ? 'detected' : 'not-detected'}">${verdict.label}</div>
    <div class="checks-list">
      ${groupsHtml}
      ${intelSection}
    </div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    renderOverview(resultsEl._scan, resultsEl._cached);
  });
}

// ── Scan orchestrator ─────────────────────────────────────────
// Centralized state for the scan lifecycle. Previously this was spread
// across `activePort`, `resultsEl._scan`, `resultsEl._cached`, and ad-hoc
// button-disable toggles in three different places (result/error/disconnect
// handlers) — easy to forget one when adding a new exit path. Now there's
// one place that knows what "idle" means.
const appState = {
  activePort: null,
  lastResult: null,
  lastCached: false,
};

function setUiIdle() {
  appState.activePort   = null;
  scanBtn.disabled       = false;
  rescanBtn.disabled     = false;
  showProgress(false);
}

function resetScanState() {
  appState.lastResult = null;
  appState.lastCached = false;
  resultsEl._scan   = null;
  resultsEl._cached = false;
}

function doScan(domain, forceRefresh) {
  if (!isValidDomain(domain)) {
    setStatus('Invalid input — enter a domain (example.com) or IP (1.2.3.4)');
    return;
  }

  // Abort any in-flight scan
  if (appState.activePort) { try { appState.activePort.disconnect(); } catch {} appState.activePort = null; }

  resetScanState();
  setStatus('Scanning…', 'scanning');
  resultsEl.innerHTML = '';
  showProgress(true);
  updateProgress(0, 'Connecting…');
  scanBtn.disabled   = true;
  rescanBtn.disabled = true;

  const port = chrome.runtime.connect({ name: 'scan' });
  appState.activePort = port;

  port.onMessage.addListener(msg => {
    if (msg.type === 'progress') {
      updateProgress(msg.pct, msg.activity);

    } else if (msg.type === 'result') {
      setUiIdle();

      const result = msg.data;
      const cached = !!msg.cached;

      appState.lastResult = result;
      appState.lastCached = cached;
      resultsEl._scan   = result;
      resultsEl._cached = cached;
      renderOverview(result, cached);

    } else if (msg.type === 'error') {
      setUiIdle();
      resetScanState();
      setStatus(`Scan failed — ${msg.message || 'unknown error'}`);
    }
  });

  port.onDisconnect.addListener(() => {
    if (appState.activePort) {
      setUiIdle();
      // Only show a disconnect error if no result ever arrived for this scan
      if (!appState.lastResult) {
        resetScanState();
        setStatus('Disconnected — try again');
      }
    }
  });

  port.postMessage({ action: 'scan', domain, forceRefresh: !!forceRefresh });
}

// ── Button handlers ───────────────────────────────────────────
function getDomain() {
  let v = domainInput.value.trim().toLowerCase();
  if (!v) return v;

  // Allow pasted full URLs: strip scheme, then path/query/fragment.
  v = v.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');
  // IPv6 in bracket notation must be peeled before we touch ':' or '/' generically,
  // e.g. "[2606:4700::1]:443/path" or "[2606:4700::1]".
  const bracketMatch = v.match(/^\[([0-9a-f:]+)\](?::\d+)?(\/.*)?$/i);
  if (bracketMatch) {
    v = bracketMatch[1];
  } else {
    // Strip any path/query/fragment, then a trailing :port (but never touch
    // a bare, unbracketed IPv6 address — those contain multiple ':' and have
    // no path component to strip in normal usage).
    v = v.replace(/[/?#].*$/, '');
    if (!v.includes('::') && v.split(':').length === 2) v = v.split(':')[0];
  }

  v = v.trim();
  // Collapse internal whitespace some users paste accidentally, and drop a
  // trailing root-zone dot ("example.com." is a valid but unusual FQDN form).
  v = v.replace(/\s+/g, '').replace(/\.$/, '');

  // Best-effort IDN → punycode so DoH/RDAP lookups behave for non-ASCII domains.
  if (/[^\x00-\x7f]/.test(v) && !isIPv4(v) && !isIPv6(v)) {
    try { v = new URL(`https://${v}`).hostname; } catch { /* leave as-is, validation will reject if truly invalid */ }
  }

  return v;
}

scanBtn.addEventListener('click', () => {
  const d = getDomain();
  domainInput.value = d;
  doScan(d, false);
});

rescanBtn.addEventListener('click', () => {
  const d = getDomain();
  domainInput.value = d;
  doScan(d, true);
});

domainInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') scanBtn.click();
});

// ── History view ───────────────────────────────────────────────
function renderHistory(list) {
  if (!list.length) {
    resultsEl.innerHTML = `
      <div class="detail-header">
        <button class="back-btn" id="backBtn">← Back</button>
        <span class="detail-name">Scan History</span>
      </div>
      <div class="empty-state">No scans yet.</div>`;
    document.getElementById('backBtn').addEventListener('click', () => {
      if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached);
      else resultsEl.innerHTML = '';
    });
    return;
  }

  const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const rows = list.map(e => {
    const date = new Date(e.ts).toLocaleString();
    const names = e.detected.map(id => PROVIDER_UI[id]?.name || id).join(', ') || 'None detected';
    const tag = e.isDirectIP ? ' <span class="history-ip-tag">IP</span>' : '';
    return `
      <div class="history-row" data-domain="${escHtml(e.domain)}">
        <div class="history-row-top">
          <strong>${escHtml(e.domain)}</strong>${tag}
          <span class="history-date">${escHtml(date)}</span>
        </div>
        <div class="history-row-providers">${escHtml(names)}</div>
      </div>`;
  }).join('');

  resultsEl.innerHTML = `
    <div class="detail-header">
      <button class="back-btn" id="backBtn">← Back</button>
      <span class="detail-name">Scan History</span>
      <button class="btn-icon" id="clearHistoryBtn" title="Clear history">✕</button>
    </div>
    <div class="checks-list history-list">${rows}</div>`;

  document.getElementById('backBtn').addEventListener('click', () => {
    if (resultsEl._scan) renderOverview(resultsEl._scan, resultsEl._cached);
    else resultsEl.innerHTML = '';
  });
  document.getElementById('clearHistoryBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => renderHistory([]));
  });
  resultsEl.querySelectorAll('.history-row').forEach(row => {
    row.addEventListener('click', () => {
      const d = row.dataset.domain;
      domainInput.value = d;
      doScan(d, false);
    });
  });
}

historyBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'getHistory' }, res => {
    renderHistory(res?.history || []);
  });
});
