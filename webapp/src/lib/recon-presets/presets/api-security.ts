import type { ReconPreset } from '../types'

export const API_SECURITY: ReconPreset = {
  id: 'api-security',
  name: 'API Security Audit',
  icon: '',
  image: '/preset-api.svg',
  shortDescription: 'Focused on REST/GraphQL API surface. Kiterunner, Arjun, ffuf with API extensions, Nuclei API tags.',
  fullDescription: `### Pipeline Goal
Map and test the API attack surface. This preset combines API-specific endpoint discovery (Kiterunner with large route wordlists), hidden parameter detection (Arjun on all HTTP methods), directory fuzzing with API file extensions, and Nuclei templates targeting API vulnerabilities. Everything else is stripped down to minimize noise and focus on APIs.

### Who is this for?
Pentesters and security engineers testing REST APIs, GraphQL endpoints, or microservice architectures. Applications where the primary attack surface is the API layer, not the traditional web frontend. Mobile app backends, SPAs with API-driven architectures, or headless services.

### What it enables
- Subdomain discovery (all tools) to find API subdomains (api.*, graphql.*, v1.*, etc.)
- httpx probing with tech detection and response capture
- Katana depth 2 with JS crawl to discover API endpoints referenced in frontend code
- Kiterunner with routes-large wordlist for comprehensive API route brute-forcing
- Arjun on all 5 HTTP methods (GET/POST/PUT/DELETE/PATCH) with 150 max endpoints
- ffuf with API-specific extensions (.json, .xml, .graphql, .yaml, .wadl, .wsdl) and smart fuzz
- jsluice to extract API endpoints from JavaScript files
- Nuclei DAST mode with Interactsh for API-specific vulnerability testing

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- API testing targets known HTTP endpoints
- Hakrawler -- Katana covers crawling, Kiterunner handles API-specific discovery
- GAU, ParamSpider -- historical archives less relevant for API testing
- JS Recon -- deep JS analysis not the focus; jsluice covers endpoint extraction
- Banner grabbing, Wappalyzer -- not relevant for API-focused testing
- All OSINT enrichment -- not relevant for API vulnerability discovery
- Security checks -- header checks are secondary to API logic vulnerabilities
- CVE lookup, MITRE enrichment -- Nuclei handles vulnerability detection directly

### How it works
1. Subdomain discovery finds all subdomains, including API-specific ones
2. httpx probes discovered hosts and captures response bodies for API detection
3. Katana crawls frontend code to discover API endpoint references
4. Kiterunner brute-forces API routes using 140k+ Swagger/OpenAPI route patterns
5. ffuf fuzzes directories with API-specific extensions to find undocumented endpoints
6. Arjun discovers hidden parameters on all found endpoints across all HTTP methods
7. jsluice extracts API URLs and secrets from JavaScript files
8. Nuclei runs API-targeted templates in DAST mode with OOB detection`,
  parameters: {
    // Modules: domain discovery + http probe + resource enum + vuln scan
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: true,
    subfinderEnabled: true,
    amassEnabled: true,
    amassActive: false,
    amassBrute: false,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- DISABLE port scanning ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: tech detect + response capture for API detection ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 75,
    httpxFollowRedirects: true,
    httpxMaxRedirects: 10,
    httpxProbeStatusCode: true,
    httpxProbeContentLength: true,
    httpxProbeContentType: true,
    httpxProbeTitle: true,
    httpxProbeServer: true,
    httpxProbeResponseTime: true,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTlsInfo: true,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: true,
    httpxIncludeResponseHeaders: true,

    // --- DISABLE Wappalyzer ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- Katana: moderate crawl for API endpoint discovery in frontend ---
    katanaEnabled: true,
    katanaDepth: 2,
    katanaMaxUrls: 500,
    katanaRateLimit: 75,
    katanaTimeout: 1800,
    katanaJsCrawl: true,

    // --- DISABLE Hakrawler (Kiterunner handles API discovery) ---
    hakrawlerEnabled: false,

    // --- DISABLE GAU & ParamSpider ---
    gauEnabled: false,
    paramspiderEnabled: false,

    // --- jsluice: extract API endpoints from JS ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 200,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- DISABLE JS Recon (jsluice covers endpoint extraction) ---
    jsReconEnabled: false,

    // --- ffuf: API-specific extensions, smart fuzz ---
    ffufEnabled: true,
    ffufThreads: 40,
    ffufRate: 0,
    ffufTimeout: 10,
    ffufMaxTime: 900,
    ffufExtensions: ['.json', '.xml', '.graphql', '.yaml', '.wadl', '.wsdl'],
    ffufRecursion: false,
    ffufAutoCalibrate: true,
    ffufFollowRedirects: false,
    ffufSmartFuzz: true,

    // --- Kiterunner: routes-large, high concurrency ---
    kiterunnerEnabled: true,
    kiterunnerWordlists: ['routes-large'],
    kiterunnerRateLimit: 150,
    kiterunnerConnections: 150,
    kiterunnerTimeout: 10,
    kiterunnerScanTimeout: 1200,
    kiterunnerThreads: 50,
    kiterunnerDetectMethods: true,
    kiterunnerMethodDetectionMode: 'bruteforce',
    kiterunnerBruteforceMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],

    // --- Arjun: all 5 HTTP methods, high endpoint limit ---
    arjunEnabled: true,
    arjunThreads: 5,
    arjunTimeout: 15,
    arjunScanTimeout: 900,
    arjunMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    arjunMaxEndpoints: 150,
    arjunChunkSize: 500,
    arjunPassive: false,

    // --- Nuclei: DAST + Interactsh for API vulns ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
    nucleiRateLimit: 100,
    nucleiBulkSize: 25,
    nucleiConcurrency: 25,
    nucleiTimeout: 10,
    nucleiRetries: 2,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiHeadless: false,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: true,

    // --- DISABLE CVE lookup & MITRE ---
    cveLookupEnabled: false,
    mitreEnabled: false,

    // --- DISABLE security checks ---
    securityCheckEnabled: false,

    // --- DISABLE all OSINT ---
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    urlscanEnabled: false,
    otxEnabled: false,
    censysEnabled: false,
    fofaEnabled: false,
    netlasEnabled: false,
    virusTotalEnabled: false,
    zoomEyeEnabled: false,
    criminalIpEnabled: false,
    uncoverEnabled: false,
  },
}
