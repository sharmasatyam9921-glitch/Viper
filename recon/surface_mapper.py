#!/usr/bin/env python3
"""
VIPER Surface Mapper - Attack Surface Discovery

Features:
- Parameter discovery
- JavaScript file extraction and analysis
- API endpoint enumeration
- Swagger/OpenAPI detection
- Form discovery
- Hidden input fields
- Comment extraction
"""

import asyncio
import logging

logger = logging.getLogger("viper.surface_mapper")
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


HACKAGENT_DIR = Path(__file__).parent.parent
SURFACE_OUTPUT_DIR = HACKAGENT_DIR / "data" / "surface"
SURFACE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class SurfaceMap:
    """Attack surface mapping results"""
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Parameters
    url_parameters: Dict[str, Set[str]] = field(default_factory=dict)  # url -> {params}
    form_parameters: Dict[str, List[Dict]] = field(default_factory=dict)  # url -> [form_info]
    hidden_fields: Dict[str, List[str]] = field(default_factory=dict)  # url -> [hidden values]
    
    # JavaScript
    js_files: Set[str] = field(default_factory=set)
    js_endpoints: Set[str] = field(default_factory=set)
    js_secrets: List[Dict] = field(default_factory=list)
    
    # API
    api_endpoints: Set[str] = field(default_factory=set)
    swagger_urls: Set[str] = field(default_factory=set)
    graphql_endpoints: Set[str] = field(default_factory=set)
    
    # Content
    html_comments: List[str] = field(default_factory=list)
    interesting_paths: Set[str] = field(default_factory=set)
    
    # Errors/Info leaks
    error_messages: List[Dict] = field(default_factory=list)
    version_info: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "url_parameters": {k: list(v) for k, v in self.url_parameters.items()},
            "form_parameters": self.form_parameters,
            "hidden_fields": self.hidden_fields,
            "js_files": list(self.js_files),
            "js_endpoints": list(self.js_endpoints),
            "js_secrets": self.js_secrets,
            "api_endpoints": list(self.api_endpoints),
            "swagger_urls": list(self.swagger_urls),
            "graphql_endpoints": list(self.graphql_endpoints),
            "html_comments": self.html_comments,
            "interesting_paths": list(self.interesting_paths),
            "error_messages": self.error_messages,
            "version_info": self.version_info
        }
    
    def save(self, filename: str = None) -> Path:
        if not filename:
            safe_target = re.sub(r'[^\w\-_.]', '_', self.target)
            filename = f"surface_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = SURFACE_OUTPUT_DIR / filename
        filepath.write_text(json.dumps(self.to_dict(), indent=2))
        return filepath


class SurfaceMapper:
    """
    Maps the attack surface of a web application.
    
    Discovers parameters, endpoints, APIs, and information leaks.
    """
    
    # Common API paths to check
    API_PATHS = [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/rest', '/graphql', '/gql',
        '/swagger.json', '/swagger/v1/swagger.json',
        '/openapi.json', '/api-docs', '/api/docs',
        '/swagger-ui.html', '/swagger-ui/',
        '/v1', '/v2', '/v3',
        '/.well-known/openapi.json',
        '/api/swagger.json', '/api/openapi.json',
        '/doc', '/docs', '/documentation',
        '/api/schema', '/schema'
    ]
    
    # Patterns to find in JS files
    JS_PATTERNS = {
        'api_endpoints': [
            r'["\']/(api|rest)/[^"\']+["\']',
            r'fetch\s*\(\s*["\'][^"\']+["\']',
            r'axios\.[a-z]+\s*\(\s*["\'][^"\']+["\']',
            r'XMLHttpRequest.*open\s*\([^)]+["\'][^"\']+["\']',
            r'url:\s*["\'][^"\']+["\']',
            r'endpoint:\s*["\'][^"\']+["\']',
        ],
        'secrets': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Z0-9]+)["\']',
            r'AKIA[A-Z0-9]{16}',  # AWS Access Key
            r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        ],
        'interesting': [
            r'admin',
            r'debug',
            r'test',
            r'internal',
            r'staging',
            r'localhost',
        ]
    }
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
    
    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [SURFACE] [{level}] {msg}")
    
    async def map_surface(self, target: str, 
                          crawl_depth: int = 2,
                          max_pages: int = 50) -> SurfaceMap:
        """
        Map the attack surface of a target.
        
        Args:
            target: Base URL to map
            crawl_depth: How deep to crawl
            max_pages: Maximum pages to analyze
        """
        surface = SurfaceMap(target=target)
        
        self.log(f"Mapping attack surface: {target}")
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as self.session:
            
            # 1. Check for API documentation
            self.log("Phase 1: API Documentation Discovery")
            await self._discover_api_docs(target, surface)
            
            # 2. Crawl and analyze pages
            self.log("Phase 2: Crawling and Parameter Discovery")
            await self._crawl_and_analyze(target, surface, crawl_depth, max_pages)
            
            # 3. Analyze JavaScript files
            if surface.js_files:
                self.log(f"Phase 3: Analyzing {len(surface.js_files)} JS files")
                await self._analyze_js_files(surface)
            
            # 4. Check for GraphQL
            self.log("Phase 4: GraphQL Detection")
            await self._detect_graphql(target, surface)
        
        # Save results
        saved_path = surface.save()
        self.log(f"Surface mapping complete. Results saved to: {saved_path}")
        
        return surface
    
    async def _discover_api_docs(self, target: str, surface: SurfaceMap):
        """Check for API documentation endpoints"""
        base = target.rstrip('/')
        
        async def check_path(path: str) -> Optional[Tuple[str, str]]:
            url = f"{base}{path}"
            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Check if it looks like API docs
                        if any(marker in content.lower() for marker in 
                               ['swagger', 'openapi', 'api', 'endpoint', 'paths']):
                            return (url, content)
            except Exception as e:  # noqa: BLE001
                pass
            return None
        
        tasks = [check_path(p) for p in self.API_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple):
                url, content = result
                surface.swagger_urls.add(url)
                self.log(f"  Found API docs: {url}", "FOUND")
                
                # Try to extract endpoints from swagger/openapi
                await self._parse_api_spec(content, surface)
    
    async def _parse_api_spec(self, content: str, surface: SurfaceMap):
        """Parse OpenAPI/Swagger spec to extract endpoints"""
        try:
            spec = json.loads(content)
            
            # OpenAPI 3.x
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    surface.api_endpoints.add(path)
                    if isinstance(methods, dict):
                        for method, details in methods.items():
                            if isinstance(details, dict):
                                # Extract parameters
                                params = details.get('parameters', [])
                                param_names = [p.get('name') for p in params if isinstance(p, dict)]
                                if param_names:
                                    surface.url_parameters[path] = set(param_names)
            
            # Version info
            if 'info' in spec and isinstance(spec['info'], dict):
                version = spec['info'].get('version')
                if version:
                    surface.version_info.append(f"API Version: {version}")
        except Exception as e:  # noqa: BLE001
            pass
    
    async def _crawl_and_analyze(self, target: str, surface: SurfaceMap, 
                                  depth: int, max_pages: int):
        """Crawl pages and extract information"""
        to_visit = [(target, 0)]
        self.visited_urls.clear()
        
        while to_visit and len(self.visited_urls) < max_pages:
            url, current_depth = to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
            
            if current_depth > depth:
                continue
            
            self.visited_urls.add(url)
            
            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        continue
                    
                    content_type = resp.headers.get('Content-Type', '')
                    if 'html' not in content_type.lower():
                        continue
                    
                    body = await resp.text()
                    
                    # Analyze page
                    await self._analyze_page(url, body, surface)
                    
                    # Extract links for crawling
                    if current_depth < depth:
                        links = await self._extract_links(url, body)
                        for link in links:
                            if link not in self.visited_urls:
                                to_visit.append((link, current_depth + 1))
            except Exception as e:  # noqa: BLE001
                continue
    
    async def _analyze_page(self, url: str, body: str, surface: SurfaceMap):
        """Analyze a single page for attack surface elements"""
        
        # Extract URL parameters
        parsed = urlparse(url)
        if parsed.query:
            params = set(parse_qs(parsed.query).keys())
            if params:
                surface.url_parameters[url] = params
        
        if BS4_AVAILABLE:
            soup = BeautifulSoup(body, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for inp in form.find_all(['input', 'select', 'textarea']):
                    input_info = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                    
                    # Track hidden fields separately
                    if inp.get('type') == 'hidden' and inp.get('value'):
                        if url not in surface.hidden_fields:
                            surface.hidden_fields[url] = []
                        surface.hidden_fields[url].append(f"{inp.get('name')}={inp.get('value')}")
                
                if url not in surface.form_parameters:
                    surface.form_parameters[url] = []
                surface.form_parameters[url].append(form_info)
            
            # Extract JS files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                surface.js_files.add(js_url)
            
            # Extract HTML comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text))
            for comment in comments:
                text = str(comment).strip()
                if len(text) > 10 and len(text) < 500:  # Filter noise
                    surface.html_comments.append(text)
            
            # Also find comment nodes
            from bs4 import Comment
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                text = str(comment).strip()
                if len(text) > 10 and len(text) < 500:
                    surface.html_comments.append(text)
        else:
            # Regex fallback
            # Extract form inputs
            form_matches = re.findall(r'<form[^>]*>.*?</form>', body, re.I | re.S)
            for form_html in form_matches:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.I)
                if inputs:
                    if url not in surface.form_parameters:
                        surface.form_parameters[url] = []
                    surface.form_parameters[url].append({
                        'inputs': [{'name': i} for i in inputs]
                    })
            
            # Extract JS files
            js_matches = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
            for js in js_matches:
                surface.js_files.add(urljoin(url, js))
            
            # Extract comments
            comments = re.findall(r'<!--(.+?)-->', body, re.S)
            for comment in comments:
                text = comment.strip()
                if 10 < len(text) < 500:
                    surface.html_comments.append(text)
        
        # Check for error messages / stack traces
        error_patterns = [
            (r'(Exception|Error|Warning|Notice):.+', 'error_message'),
            (r'at\s+[\w\.]+\([\w\.]+:\d+\)', 'stack_trace'),
            (r'line\s+\d+', 'line_reference'),
            (r'(Fatal|Parse)\s+error:', 'php_error'),
            (r'Traceback \(most recent call last\)', 'python_traceback'),
        ]
        
        for pattern, error_type in error_patterns:
            matches = re.findall(pattern, body, re.I)
            for match in matches[:3]:  # Limit per type
                surface.error_messages.append({
                    'type': error_type,
                    'url': url,
                    'snippet': match[:200]
                })
        
        # Extract version info
        version_patterns = [
            r'version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'([A-Za-z]+)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, body, re.I)
            for match in matches[:5]:
                if isinstance(match, tuple):
                    surface.version_info.append(' '.join(match))
                else:
                    surface.version_info.append(match)
    
    async def _extract_links(self, base_url: str, body: str) -> List[str]:
        """Extract links from page"""
        links = []
        parsed_base = urlparse(base_url)
        
        if BS4_AVAILABLE:
            soup = BeautifulSoup(body, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                
                # Only follow links to same domain
                if parsed.netloc == parsed_base.netloc:
                    links.append(full_url)
        else:
            href_matches = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
            for href in href_matches:
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == parsed_base.netloc:
                    links.append(full_url)
        
        return list(set(links))
    
    async def _analyze_js_files(self, surface: SurfaceMap):
        """Analyze JavaScript files for endpoints and secrets"""
        
        for js_url in list(surface.js_files)[:20]:  # Limit JS files
            try:
                async with self.session.get(js_url) as resp:
                    if resp.status != 200:
                        continue
                    
                    js_content = await resp.text()
                    
                    # Find API endpoints
                    for pattern in self.JS_PATTERNS['api_endpoints']:
                        matches = re.findall(pattern, js_content, re.I)
                        for match in matches:
                            # Clean up the match
                            endpoint = match.strip('"\'')
                            if '/' in endpoint and len(endpoint) < 200:
                                surface.js_endpoints.add(endpoint)
                    
                    # Find secrets
                    for pattern in self.JS_PATTERNS['secrets']:
                        matches = re.findall(pattern, js_content, re.I)
                        for match in matches:
                            if len(match) > 5:  # Avoid false positives
                                surface.js_secrets.append({
                                    'source': js_url,
                                    'pattern': pattern[:30],
                                    'value': match[:100]  # Truncate
                                })
                                self.log(f"  [!] Potential secret in {js_url}", "VULN")
            except Exception as e:  # noqa: BLE001
                continue
    
    async def _detect_graphql(self, target: str, surface: SurfaceMap):
        """Detect GraphQL endpoints"""
        base = target.rstrip('/')
        graphql_paths = ['/graphql', '/gql', '/api/graphql', '/v1/graphql', '/query']
        
        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }
        
        for path in graphql_paths:
            url = f"{base}{path}"
            try:
                # Try POST with introspection
                async with self.session.post(
                    url,
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'}
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if '__schema' in body or 'types' in body:
                            surface.graphql_endpoints.add(url)
                            self.log(f"  GraphQL found: {url}", "FOUND")
                            
                            # Check if introspection is enabled (security issue)
                            if '__schema' in body:
                                surface.error_messages.append({
                                    'type': 'graphql_introspection',
                                    'url': url,
                                    'snippet': 'GraphQL introspection enabled'
                                })
                                self.log(f"  [!] GraphQL introspection enabled!", "VULN")
            except Exception as e:  # noqa: BLE001
                continue


async def main():
    """CLI interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("VIPER Surface Mapper")
        print()
        print("Usage:")
        print("  python surface_mapper.py <url>    # Map attack surface")
        print("  python surface_mapper.py <url> 3  # Crawl depth 3")
        return
    
    target = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    
    mapper = SurfaceMapper()
    surface = await mapper.map_surface(target, crawl_depth=depth)
    
    print(f"\n=== Surface Map for {target} ===")
    print(f"URL Parameters: {sum(len(v) for v in surface.url_parameters.values())}")
    print(f"Forms: {sum(len(v) for v in surface.form_parameters.values())}")
    print(f"JS Files: {len(surface.js_files)}")
    print(f"JS Endpoints: {len(surface.js_endpoints)}")
    print(f"JS Secrets: {len(surface.js_secrets)}")
    print(f"API Endpoints: {len(surface.api_endpoints)}")
    print(f"Swagger URLs: {len(surface.swagger_urls)}")
    print(f"GraphQL: {len(surface.graphql_endpoints)}")
    print(f"Comments: {len(surface.html_comments)}")
    print(f"Errors: {len(surface.error_messages)}")


if __name__ == "__main__":
    asyncio.run(main())
