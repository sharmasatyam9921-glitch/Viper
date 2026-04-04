import type { ReconPreset } from '../types'

export const SUBDOMAIN_TAKEOVER: ReconPreset = {
  id: 'subdomain-takeover',
  name: 'Subdomain Takeover Hunter',
  icon: '',
  image: '/preset-capture.svg',
  shortDescription: 'Maximize subdomain discovery and detect takeover opportunities. Enables all subdomain tools at high limits, httpx CNAME probing, and Nuclei takeover templates.',
  fullDescription: `### Pipeline Goal
Discover every subdomain and identify takeover opportunities. This preset maximizes subdomain enumeration with all tools at high limits, enables brute-forcing and active Amass, then probes for dangling CNAMEs and 404 patterns using httpx. Nuclei runs only takeover-specific templates to flag exploitable dangling records.

### Who is this for?
Bug bounty hunters and security teams looking for subdomain takeover vulnerabilities -- one of the most common and rewarding finding categories. Also useful for asset inventory teams that need to audit DNS hygiene across large domains.

### What it enables
- All subdomain discovery tools (crt.sh, HackerTarget, Knockpy, Subfinder, Amass, Puredns) at 10000 max results each
- Amass active mode + brute-force for deeper enumeration
- Puredns and bruteforce wordlist for DNS resolution and wildcard filtering
- WHOIS and DNS lookups for ownership and record analysis
- httpx with CNAME, status code, title, IP, tech detect, and TLS probes -- essential for detecting dangling records
- GAU enabled for passive historical subdomain data from Wayback Machine and other archives
- Nuclei with takeover tags only -- laser-focused on subdomain takeover detection templates

### What it disables
- Port scanning (Naabu, Nmap, Masscan) -- not relevant to subdomain takeover hunting
- Web crawlers (Katana, Hakrawler) -- not crawling content, just probing subdomains
- Directory fuzzing (ffuf, Kiterunner) -- not relevant
- Parameter discovery (Arjun, ParamSpider) -- not relevant
- JS analysis (jsluice, JS Recon) -- not relevant
- Wappalyzer, banner grabbing -- unnecessary overhead
- Heavy httpx probes (JARM, favicon, ASN, CDN, response body, word/line count) -- not needed for takeover detection
- CVE lookup, MITRE enrichment -- not relevant to takeover hunting
- Security checks -- disabled to keep the scan focused
- All OSINT enrichment providers -- disabled for speed

### How it works
1. All subdomain discovery tools run at high limits with brute-forcing enabled
2. Amass runs in active mode with brute-force for maximum coverage
3. Puredns resolves and filters wildcard subdomains
4. httpx probes every discovered subdomain, extracting CNAME records and status codes
5. GAU pulls historical subdomain data from web archives
6. Nuclei runs takeover-specific templates against all probed hosts to detect exploitable dangling records`,
  parameters: {
    // Pipeline modules: domain_discovery + http_probe + vuln_scan (for Nuclei takeover)
    scanModules: ['domain_discovery', 'http_probe', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: ALL tools at 10000 max ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    crtshMaxResults: 10000,
    hackerTargetEnabled: true,
    hackerTargetMaxResults: 10000,
    knockpyReconEnabled: true,
    knockpyReconMaxResults: 10000,
    subfinderEnabled: true,
    subfinderMaxResults: 10000,
    amassEnabled: true,
    amassActive: true,
    amassBrute: true,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: true,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- Port Scanning: ALL disabled ---
    naabuEnabled: false,
    nmapEnabled: false,
    masscanEnabled: false,

    // --- httpx: essential probes for CNAME/takeover detection ---
    httpxEnabled: true,
    httpxFollowRedirects: true,
    httpxProbeStatusCode: true,
    httpxProbeTitle: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTechDetect: true,
    httpxProbeTlsInfo: true,
    // Disable heavy probes not needed for takeover detection
    httpxProbeJarm: false,
    httpxProbeFavicon: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeTlsGrab: false,

    // --- Wappalyzer: disabled ---
    wappalyzerEnabled: false,

    // --- Banner Grabbing: disabled ---
    bannerGrabEnabled: false,

    // --- GAU: enabled for passive historical subdomain data ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauVerifyUrls: false,

    // --- Crawlers: disabled ---
    katanaEnabled: false,
    hakrawlerEnabled: false,

    // --- Parameter discovery: disabled ---
    paramspiderEnabled: false,

    // --- JS analysis: disabled ---
    jsluiceEnabled: false,
    jsReconEnabled: false,

    // --- Directory/API fuzzing: disabled ---
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,

    // --- Nuclei: takeover templates only ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium'],
    nucleiDastMode: false,
    nucleiHeadless: false,
    nucleiInteractsh: false,
    nucleiTags: ['takeover'],

    // --- CVE / MITRE: disabled ---
    cveLookupEnabled: false,
    mitreEnabled: false,

    // --- Security checks: disabled ---
    securityCheckEnabled: false,

    // --- OSINT: all disabled ---
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    censysEnabled: false,
    urlscanEnabled: false,
    otxEnabled: false,
    fofaEnabled: false,
    netlasEnabled: false,
    virusTotalEnabled: false,
    zoomEyeEnabled: false,
    criminalIpEnabled: false,
    uncoverEnabled: false,
  },
}
