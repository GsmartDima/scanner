"""
Asset Discovery Module
Handles DNS enumeration, subdomain discovery, and HTTP(S) probing
"""
import asyncio
import ssl
import socket
import dns.resolver
import dns.exception
import httpx
import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse
import logging
from datetime import datetime

from models import Asset, Lead
from config import settings
from modules.security_utils import validate_external_url, is_safe_domain

logger = logging.getLogger(__name__)


class AssetDiscoverer:
    """Discovers assets for a given domain"""
    
    def __init__(self, dns_concurrency: int = 50, http_concurrency: int = 30, http_timeout: int = 5):
        self.timeout = settings.subdomain_timeout
        self.max_subdomains = 50
        self.http_timeout = http_timeout  # Configurable HTTP timeout
        self.dns_concurrency = dns_concurrency  # Configurable DNS concurrency
        self.http_concurrency = http_concurrency  # Configurable HTTP concurrency
        
        # Enhanced subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'lyncdiscover',
            'sip', 'test', 'staging', 'dev', 'development', 'prod', 'production',
            'api', 'app', 'admin', 'vpn', 'portal', 'blog', 'shop', 'store',
            'remote', 'citrix', 'owa', 'exchange', 'sharepoint', 'confluence',
            # Additional comprehensive list
            'secure', 'server', 'ns', 'email', 'demo', 'shop', 'forum', 'www1', 'www2',
            'ns3', 'dns', 'search', 'support', 'beta', 'members', 'www-dev', 'staging-api',
            'preview', 'mobile', 'm', 'cdn', 'assets', 'static', 'img', 'video', 'pics',
            'photos', 'download', 'downloads', 'ftp2', 'backup', 'old', 'new', 'help',
            'kb', 'docs', 'documentation', 'wiki', 'crm', 'erp', 'intranet', 'extranet',
            'vpn', 'ssh', 'ssl', 'secure-mail', 'webmail2', 'mail2', 'smtp2', 'pop3',
            'imap', 'calendar', 'contacts', 'files', 'drive', 'cloud', 'git', 'svn',
            'jenkins', 'ci', 'build', 'deploy', 'monitor', 'log', 'logs', 'stats',
            'analytics', 'reports', 'dashboard', 'cpanel', 'plesk', 'phpmyadmin',
            'mysql', 'postgres', 'db', 'database', 'redis', 'mongo', 'elastic',
            'kibana', 'grafana', 'prometheus', 'nagios', 'zabbix', 'cacti',
            'billing', 'invoice', 'payment', 'shop', 'cart', 'checkout', 'order',
            'customer', 'client', 'partner', 'vendor', 'supplier', 'affiliate',
            'tracking', 'trace', 'debug', 'error', 'exception', 'status', 'health'
        ]
        
        # Ports to probe for HTTP services
        self.http_ports = [80, 443, 8000, 8080, 8443, 8888, 9000, 9443]
    
    async def discover_assets(self, lead: Lead, max_subdomains: int = None) -> List[Asset]:
        """Discover all assets for a domain with enhanced techniques and maximum parallelization"""
        if max_subdomains:
            self.max_subdomains = max_subdomains
            
        logger.info(f"Starting enhanced asset discovery for {lead.domain}")
        
        # Run DNS enumeration and subdomain discovery in parallel
        dns_task = asyncio.create_task(self.dns_enumeration(lead.domain))
        subdomains_task = asyncio.create_task(self.discover_subdomains_enhanced(lead.domain))
        
        # Wait for both to complete
        dns_records, subdomains = await asyncio.gather(dns_task, subdomains_task)
        
        # Limit subdomains
        if len(subdomains) > self.max_subdomains:
            logger.warning(f"Found {len(subdomains)} subdomains for {lead.domain}, limiting to {self.max_subdomains}")
            # Sort by likelihood of being important (shorter names first, www first, etc.)
            sorted_subdomains = sorted(subdomains, key=lambda x: (
                0 if x.startswith('www.') else 1,
                0 if x.startswith('api.') else 1,
                0 if x.startswith('mail.') else 1,
                len(x.split('.')[0]),  # Prefer shorter subdomain names
                x
            ))
            subdomains = sorted_subdomains[:self.max_subdomains]
        
        # Add main domain to subdomains
        all_domains = [lead.domain] + list(subdomains)
        
        # Probe HTTP(S) services with maximum parallelization
        assets = await self.probe_http_services_parallel(all_domains, lead.domain)
        
        logger.info(f"Enhanced discovery found {len(assets)} assets for {lead.domain}")
        return assets
    
    async def dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        """Perform DNS enumeration for various record types"""
        records = {
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'MX': [],
            'TXT': [],
            'NS': []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    if record_type == 'MX':
                        records[record_type].append(f"{answer.preference} {answer.exchange}")
                    else:
                        records[record_type].append(str(answer))
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception as e:
                logger.warning(f"DNS error for {domain} {record_type}: {str(e)}")
        
        logger.debug(f"DNS enumeration for {domain}: {records}")
        return records
    
    async def discover_subdomains_enhanced(self, domain: str) -> Set[str]:
        """Enhanced subdomain discovery using multiple techniques in parallel"""
        logger.info(f"Starting enhanced subdomain enumeration for {domain}")
        
        # Run ALL discovery methods in parallel for maximum speed
        tasks = [
            # Method 1: Enhanced common subdomain bruteforce
            asyncio.create_task(self._bruteforce_common_subdomains_enhanced(domain)),
            # Method 2: Certificate transparency logs (multiple sources)
            asyncio.create_task(self._certificate_transparency_search_enhanced(domain)),
            # Method 3: DNS zone transfer (unlikely to work but worth trying)
            asyncio.create_task(self._dns_zone_transfer(domain)),
            # Method 4: Search engine enumeration
            asyncio.create_task(self._search_engine_enumeration(domain)),
            # Method 5: DNS permutation scanning
            asyncio.create_task(self._permutation_scanning(domain))
        ]
        
        logger.debug("Running 5 subdomain discovery methods in parallel...")
        
        # Wait for all methods to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all results
        subdomains = set()
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Subdomain discovery method {i+1} failed: {str(result)}")
            else:
                subdomains.update(result)
                logger.debug(f"Method {i+1} found {len(result)} subdomains")
        
        # Remove the main domain from subdomains
        subdomains.discard(domain)
        
        logger.info(f"Enhanced parallel enumeration found {len(subdomains)} total subdomains for {domain}")
        return subdomains
    
    async def _bruteforce_common_subdomains_enhanced(self, domain: str) -> Set[str]:
        """Enhanced bruteforce with larger wordlist and variations"""
        found_subdomains = set()
        
        # Create variations of common subdomains
        enhanced_subdomains = set(self.common_subdomains)
        
        # Add numbered variations
        base_subs = ['www', 'mail', 'api', 'app', 'test', 'dev', 'staging']
        for base in base_subs:
            for i in range(1, 5):
                enhanced_subdomains.add(f"{base}{i}")
                enhanced_subdomains.add(f"{base}-{i}")
        
        # Add environment variations
        environments = ['dev', 'test', 'staging', 'prod', 'qa', 'uat', 'demo']
        services = ['api', 'app', 'web', 'admin', 'portal']
        for env in environments:
            for service in services:
                enhanced_subdomains.add(f"{env}-{service}")
                enhanced_subdomains.add(f"{service}-{env}")
        
        logger.debug(f"Testing {len(enhanced_subdomains)} subdomain variations")
        
        tasks = []
        for subdomain in enhanced_subdomains:
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self._check_subdomain_exists(full_domain))
        
        # Run checks concurrently with higher concurrency for enhanced speed
        semaphore = asyncio.Semaphore(self.dns_concurrency)  # Use configurable DNS concurrency
        
        async def check_with_semaphore(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(*[check_with_semaphore(task) for task in tasks], return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, bool) and result:
                subdomain = f"{list(enhanced_subdomains)[i]}.{domain}"
                found_subdomains.add(subdomain)
        
        logger.debug(f"Bruteforce found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    async def _check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if a subdomain exists via DNS resolution"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1  # Reduced from 2 to 1 second
            resolver.lifetime = 3  # Reduced from 5 to 3 seconds
            
            # Try A record first
            try:
                resolver.resolve(subdomain, 'A')
                return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Try CNAME record
            try:
                resolver.resolve(subdomain, 'CNAME')
                return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
                
            return False
            
        except Exception:
            return False
    
    async def _certificate_transparency_search_enhanced(self, domain: str) -> Set[str]:
        """Enhanced certificate transparency search using multiple sources"""
        found_subdomains = set()
        
        # Multiple CT log sources
        ct_sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        ]
        
        for source_url in ct_sources:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    if 'crt.sh' in source_url:
                        response = await client.get(source_url)
                        if response.status_code == 200:
                            data = response.json()
                            for entry in data:
                                if 'name_value' in entry:
                                    names = entry['name_value'].split('\n')
                                    for name in names:
                                        name = name.strip()
                                        if name and name.endswith(f".{domain}"):
                                            if name.startswith('*.'):
                                                name = name[2:]
                                            found_subdomains.add(name)
                    
                    elif 'certspotter' in source_url:
                        response = await client.get(source_url)
                        if response.status_code == 200:
                            data = response.json()
                            for entry in data:
                                if 'dns_names' in entry:
                                    for name in entry['dns_names']:
                                        if name.endswith(f".{domain}"):
                                            if name.startswith('*.'):
                                                name = name[2:]
                                            found_subdomains.add(name)
            
            except Exception as e:
                logger.debug(f"CT source {source_url} failed: {str(e)}")
                continue
        
        logger.debug(f"Certificate transparency found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    async def _search_engine_enumeration(self, domain: str) -> Set[str]:
        """Use search engines to find subdomains (limited by rate limiting)"""
        found_subdomains = set()
        
        # This is a simplified version - in production, you'd use proper search APIs
        # For now, we'll simulate some common patterns that search engines might reveal
        
        common_search_patterns = [
            f"www.{domain}", f"mail.{domain}", f"api.{domain}",
            f"blog.{domain}", f"shop.{domain}", f"support.{domain}",
            f"admin.{domain}", f"portal.{domain}", f"app.{domain}"
        ]
        
        # Verify these exist
        for subdomain in common_search_patterns:
            if await self._check_subdomain_exists(subdomain):
                found_subdomains.add(subdomain)
        
        logger.debug(f"Search engine simulation found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    async def _permutation_scanning(self, domain: str) -> Set[str]:
        """Generate and test permutations of the domain name"""
        found_subdomains = set()
        
        # Extract base name from domain
        base_name = domain.split('.')[0]
        
        # Common permutation patterns
        permutations = []
        
        # Add common prefixes/suffixes
        modifiers = ['dev', 'test', 'staging', 'prod', 'new', 'old', 'beta', 'alpha']
        for mod in modifiers:
            permutations.extend([
                f"{mod}-{base_name}",
                f"{base_name}-{mod}",
                f"{mod}{base_name}",
                f"{base_name}{mod}"
            ])
        
        # Test permutations
        tasks = []
        for perm in permutations[:20]:  # Limit to avoid too many requests
            full_domain = f"{perm}.{domain}"
            tasks.append(self._check_subdomain_exists(full_domain))
        
        if tasks:
            semaphore = asyncio.Semaphore(max(10, self.dns_concurrency // 2))  # Use half of DNS concurrency
            
            async def check_with_semaphore(task):
                async with semaphore:
                    return await task
            
            results = await asyncio.gather(*[check_with_semaphore(task) for task in tasks], return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, bool) and result:
                    subdomain = f"{permutations[i]}.{domain}"
                    found_subdomains.add(subdomain)
        
        logger.debug(f"Permutation scanning found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    async def _dns_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer"""
        found_subdomains = set()
        
        try:
            # Get NS records first
            resolver = dns.resolver.Resolver()
            ns_answers = resolver.resolve(domain, 'NS')
            
            for ns in ns_answers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            found_subdomains.add(subdomain)
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"Zone transfer failed for {domain}: {str(e)}")
        
        return found_subdomains
    
    async def probe_http_services(self, subdomain: str, main_domain: str) -> List[Asset]:
        """Probe HTTP/HTTPS services on various ports"""
        assets = []
        
        # Get IP address
        ip_address = await self._resolve_ip(subdomain)
        
        # Probe different ports
        for port in self.http_ports:
            for protocol in ['https', 'http']:
                if protocol == 'http' and port in [443, 8443, 9443]:
                    continue  # Skip HTTP on HTTPS ports
                if protocol == 'https' and port in [80, 8000, 8080]:
                    continue  # Skip HTTPS on HTTP ports
                
                asset = await self._probe_http_endpoint(subdomain, main_domain, ip_address, protocol, port)
                if asset:
                    assets.append(asset)
        
        return assets
    
    async def probe_http_services_parallel(self, domains: List[str], main_domain: str) -> List[Asset]:
        """Probe HTTP/HTTPS services across all domains and ports in parallel for maximum speed"""
        logger.info(f"Starting parallel HTTP probing for {len(domains)} domains")
        
        # Create IP resolution tasks for all domains first
        ip_resolution_tasks = {}
        for subdomain in domains:
            ip_resolution_tasks[subdomain] = asyncio.create_task(self._resolve_ip(subdomain))
        
        # Create all probe tasks upfront
        probe_tasks = []
        
        for subdomain in domains:
            ip_task = ip_resolution_tasks[subdomain]
            
            # Create probe tasks for each port/protocol combination
            for port in self.http_ports:
                for protocol in ['https', 'http']:
                    if protocol == 'http' and port in [443, 8443, 9443]:
                        continue  # Skip HTTP on HTTPS ports
                    if protocol == 'https' and port in [80, 8000, 8080]:
                        continue  # Skip HTTPS on HTTP ports
                    
                    # Create probe task with shared IP resolution
                    probe_task = asyncio.create_task(
                        self._probe_endpoint_with_ip_resolution(subdomain, main_domain, protocol, port, ip_task)
                    )
                    probe_tasks.append(probe_task)
        
        logger.debug(f"Created {len(probe_tasks)} HTTP probe tasks for {len(domains)} domains")
        
        # Execute all probes with controlled concurrency
        semaphore = asyncio.Semaphore(self.http_concurrency)  # Use configurable HTTP concurrency
        
        async def probe_with_semaphore(task):
            async with semaphore:
                return await task
        
        # Run all probes in parallel
        results = await asyncio.gather(
            *[probe_with_semaphore(task) for task in probe_tasks], 
            return_exceptions=True
        )
        
        # Collect successful results
        assets = []
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"HTTP probe failed: {str(result)}")
            elif result is not None:
                assets.append(result)
        
        logger.info(f"Parallel HTTP probing completed: {len(assets)} assets found")
        return assets
    
    async def _probe_endpoint_with_ip_resolution(self, subdomain: str, main_domain: str, 
                                                 protocol: str, port: int, ip_task: asyncio.Task) -> Optional[Asset]:
        """Probe a specific HTTP endpoint with IP resolution handled separately"""
        try:
            # Wait for IP resolution to complete
            ip_address = await ip_task
        except Exception:
            # If IP resolution fails, try probing anyway
            ip_address = None
            
        return await self._probe_http_endpoint(subdomain, main_domain, ip_address, protocol, port)
    
    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(domain, 'A')
            return str(answers[0])
        except Exception:
            return None
    
    async def _probe_http_endpoint(self, subdomain: str, main_domain: str, 
                                   ip_address: Optional[str], protocol: str, port: int) -> Optional[Asset]:
        """Probe a specific HTTP endpoint with SSRF protection"""
        if port == 80 and protocol == 'http':
            url = f"http://{subdomain}"
        elif port == 443 and protocol == 'https':
            url = f"https://{subdomain}"
        else:
            url = f"{protocol}://{subdomain}:{port}"
        
        # SECURITY: Validate URL against SSRF attacks
        try:
            if not is_safe_domain(subdomain):
                logger.warning(f"SSRF protection blocked unsafe domain: {subdomain}")
                return None
        except Exception as e:
            logger.warning(f"SSRF protection validation failed for {subdomain}: {e}")
            return None
        
        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout,
                verify=False,  # Skip SSL verification for discovery
                follow_redirects=False  # Don't follow redirects to detect them
            ) as client:
                
                response = await client.get(url)
                
                # Detect HTTP to HTTPS redirects
                is_redirect_only = False
                redirect_target = None
                if (protocol == 'http' and 
                    response.status_code in [301, 302, 303, 307, 308] and
                    'location' in response.headers):
                    
                    location = response.headers['location']
                    if location.startswith('https://'):
                        is_redirect_only = True
                        redirect_target = location
                        logger.debug(f"HTTP redirect detected: {url} -> {location}")
                
                # Extract information
                title = self._extract_title(response.text)
                tech_stack = self._detect_technology(response)
                
                asset = Asset(
                    domain=main_domain,
                    subdomain=subdomain,
                    ip_address=ip_address,
                    protocol=protocol,
                    port=port,
                    title=title,
                    tech_stack=tech_stack,
                    status_code=response.status_code,
                    content_length=len(response.content),
                    headers={k: v for k, v in response.headers.items()},
                    discovered_at=datetime.now(),
                    # Add redirect information
                    is_redirect_only=is_redirect_only,
                    redirect_target=redirect_target
                )
                
                logger.debug(f"Found HTTP service: {url} [{response.status_code}]")
                return asset
                
        except Exception as e:
            logger.debug(f"Failed to probe {url}: {str(e)}")
            return None
    
    def _extract_title(self, html_content: str) -> Optional[str]:
        """Extract title from HTML content"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        except Exception:
            pass
        return None
    
    def _detect_technology(self, response: httpx.Response) -> List[str]:
        """Detect technology stack from HTTP response"""
        tech_stack = []
        
        headers = response.headers
        content = response.text.lower()
        
        # Server header
        server = headers.get('server', '').lower()
        if server:
            if 'apache' in server:
                tech_stack.append('Apache')
            elif 'nginx' in server:
                tech_stack.append('Nginx')
            elif 'iis' in server:
                tech_stack.append('IIS')
            elif 'cloudflare' in server:
                tech_stack.append('Cloudflare')
        
        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if powered_by:
            if 'php' in powered_by:
                tech_stack.append('PHP')
            elif 'asp.net' in powered_by:
                tech_stack.append('ASP.NET')
            elif 'express' in powered_by:
                tech_stack.append('Express.js')
        
        # Content analysis
        if 'wordpress' in content or 'wp-content' in content:
            tech_stack.append('WordPress')
        elif 'drupal' in content:
            tech_stack.append('Drupal')
        elif 'joomla' in content:
            tech_stack.append('Joomla')
        elif 'shopify' in content:
            tech_stack.append('Shopify')
        
        # Framework detection
        if 'laravel' in content:
            tech_stack.append('Laravel')
        elif 'django' in content:
            tech_stack.append('Django')
        elif 'flask' in content:
            tech_stack.append('Flask')
        elif 'react' in content:
            tech_stack.append('React')
        elif 'angular' in content:
            tech_stack.append('Angular')
        elif 'vue' in content:
            tech_stack.append('Vue.js')
        
        # CDN detection
        if 'cloudflare' in headers.get('cf-ray', ''):
            tech_stack.append('Cloudflare')
        elif 'fastly' in headers.get('fastly-debug-digest', ''):
            tech_stack.append('Fastly')
        
        return list(set(tech_stack))  # Remove duplicates 