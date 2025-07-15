"""
DNS Security Assessment Module
Performs comprehensive DNS security analysis including DNSSEC validation,
zone transfer tests, subdomain takeover detection, and DNS infrastructure assessment.
"""
import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
import socket
import logging
import subprocess
import re
from typing import List, Dict, Any, Optional, Tuple
import httpx

from models import DNSSecurityResult, Lead
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class DNSSecurityAnalyzer:
    """DNS security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        
        # Known vulnerable DNS services for subdomain takeover
        self.takeover_signatures = {
            'github.io': [
                'There isn\'t a GitHub Pages site here.',
                'For root URLs (like http://example.com/) you must provide an index.html file'
            ],
            'herokuapp.com': [
                'No such app',
                'There\'s nothing here, yet.',
                'herokucdn.com/error-pages/no-such-app.html'
            ],
            'amazonws.com': [
                'NoSuchBucket',
                'The specified bucket does not exist'
            ],
            'azure.com': [
                'The page you are looking for cannot be found',
                'Error 404 - Web app not found'
            ],
            'cloudfront.net': [
                'Bad Request',
                'The request could not be satisfied'
            ],
            'fastly.com': [
                'Fastly error: unknown domain'
            ],
            'surge.sh': [
                'project not found'
            ],
            'bitbucket.io': [
                'Repository not found'
            ],
            'zendesk.com': [
                'Help Center Closed'
            ],
            'freshdesk.com': [
                'May be this is still fresh!'
            ],
            'shopify.com': [
                'Sorry, this shop is currently unavailable'
            ],
            'wordpress.com': [
                'Do you want to register'
            ],
            'tumblr.com': [
                'Whatever you were looking for doesn\'t currently exist'
            ]
        }
        
        # Common DNS record types to analyze
        self.record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV'
        ]
        
        # Suspicious DNS patterns
        self.suspicious_patterns = [
            r'.*\.onion$',  # Tor hidden services
            r'.*\.bit$',    # Namecoin domains
            r'.*dyn.*',     # Dynamic DNS
            r'.*no-ip.*',   # No-IP service
            r'.*ddns.*',    # Dynamic DNS
            r'.*\.tk$',     # Free domains
            r'.*\.ml$',     # Free domains
            r'.*\.ga$',     # Free domains
            r'.*\.cf$'      # Free domains
        ]
    
    async def analyze_dns_security(self, leads: List[Lead]) -> List[DNSSecurityResult]:
        """Perform comprehensive DNS security analysis"""
        logger.info(f"Starting DNS security analysis for {len(leads)} domains")
        
        results = []
        
        # Analyze each domain with limited concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent DNS tests
        
        async def limited_analysis(lead):
            async with semaphore:
                return await self._analyze_domain_dns_security(lead.domain)
        
        dns_results = await asyncio.gather(*[limited_analysis(lead) for lead in leads], 
                                         return_exceptions=True)
        
        # Filter out exceptions and None results
        for i, result in enumerate(dns_results):
            if isinstance(result, Exception):
                logger.error(f"DNS analysis failed for {leads[i].domain}: {result}")
            elif result:
                results.append(result)
        
        logger.info(f"Completed DNS security analysis: {len(results)} results")
        return results
    
    async def _analyze_domain_dns_security(self, domain: str) -> Optional[DNSSecurityResult]:
        """Analyze DNS security for a single domain"""
        try:
            # SECURITY: Validate domain before analysis
            if not is_safe_domain(domain):
                logger.warning(f"Skipping DNS analysis for potentially unsafe domain: {domain}")
                return None
            
            logger.info(f"Analyzing DNS security for {domain}")
            
            # Create result object
            result = DNSSecurityResult(domain=domain)
            
            # Test DNSSEC validation
            await self._test_dnssec(domain, result)
            
            # Analyze DNS records
            await self._analyze_dns_records(domain, result)
            
            # Test zone transfer
            await self._test_zone_transfer(domain, result)
            
            # Check subdomain takeover risks
            await self._check_subdomain_takeover(domain, result)
            
            # Analyze DNS infrastructure
            await self._analyze_dns_infrastructure(domain, result)
            
            # Check for wildcard DNS
            await self._check_wildcard_dns(domain, result)
            
            # Calculate DNS security score
            self._calculate_dns_security_score(result)
            
            # Generate recommendations
            self._generate_dns_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"DNS security analysis failed for {domain}: {str(e)}")
            return None
    
    async def _test_dnssec(self, domain: str, result: DNSSecurityResult):
        """Test DNSSEC validation"""
        try:
            logger.debug(f"Testing DNSSEC for {domain}")
            
            # Check if DNSSEC is enabled by looking for DNSKEY records
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                
                # Query for DNSKEY records
                dnskey_response = resolver.resolve(domain, 'DNSKEY')
                if dnskey_response:
                    result.dnssec_enabled = True
                    
                    # Try to validate DNSSEC
                    try:
                        # Use dig command for more comprehensive DNSSEC validation
                        cmd = ['dig', '+dnssec', '+short', domain, 'A']
                        process = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        
                        stdout, stderr = await asyncio.wait_for(
                            process.communicate(),
                            timeout=15
                        )
                        
                        output = stdout.decode().strip()
                        if 'RRSIG' in output:
                            result.dnssec_valid = True
                        else:
                            result.dnssec_errors.append("DNSSEC signatures not found")
                            
                    except Exception as e:
                        result.dnssec_errors.append(f"DNSSEC validation failed: {str(e)}")
                        
            except dns.resolver.NXDOMAIN:
                result.dnssec_errors.append("Domain does not exist")
            except dns.resolver.NoAnswer:
                result.dnssec_enabled = False
            except Exception as e:
                result.dnssec_errors.append(f"DNSSEC check failed: {str(e)}")
                
        except Exception as e:
            logger.debug(f"DNSSEC test failed for {domain}: {str(e)}")
            result.dnssec_errors.append(f"DNSSEC test error: {str(e)}")
    
    async def _analyze_dns_records(self, domain: str, result: DNSSecurityResult):
        """Analyze DNS records for security issues"""
        try:
            logger.debug(f"Analyzing DNS records for {domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            for record_type in self.record_types:
                try:
                    records = resolver.resolve(domain, record_type)
                    record_values = [str(record) for record in records]
                    result.dns_records[record_type] = record_values
                    
                    # Check for suspicious patterns
                    for record_value in record_values:
                        for pattern in self.suspicious_patterns:
                            if re.match(pattern, record_value, re.IGNORECASE):
                                result.suspicious_records.append(f"{record_type}: {record_value}")
                    
                    # Specific record type analysis
                    if record_type == 'TXT':
                        # Look for SPF, DKIM, DMARC records (handled in email security)
                        pass
                    elif record_type == 'MX':
                        # Mail server analysis (handled in email security)
                        pass
                    elif record_type == 'NS':
                        # Name server analysis
                        result.authoritative_servers.extend(record_values)
                        
                except dns.resolver.NoAnswer:
                    # No records of this type
                    pass
                except dns.resolver.NXDOMAIN:
                    result.dns_records['ERROR'] = ['Domain does not exist']
                    break
                except Exception as e:
                    logger.debug(f"Failed to resolve {record_type} for {domain}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"DNS record analysis failed for {domain}: {str(e)}")
    
    async def _test_zone_transfer(self, domain: str, result: DNSSecurityResult):
        """Test for zone transfer vulnerabilities"""
        try:
            logger.debug(f"Testing zone transfer for {domain}")
            
            # Get authoritative name servers
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                ns_records = resolver.resolve(domain, 'NS')
                nameservers = [str(ns).rstrip('.') for ns in ns_records]
            except Exception:
                nameservers = []
            
            # Test zone transfer on each nameserver
            for nameserver in nameservers[:3]:  # Limit to first 3 nameservers
                try:
                    # Resolve nameserver IP
                    ns_ip = socket.gethostbyname(nameserver)
                    
                    # Attempt zone transfer using dig
                    cmd = ['dig', '@' + ns_ip, domain, 'AXFR']
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=15
                    )
                    
                    output = stdout.decode()
                    
                    # Check if zone transfer was successful
                    if '; Transfer failed' not in output and domain in output and len(output.split('\n')) > 10:
                        result.zone_transfer_allowed = True
                        result.zone_transfer_servers.append(nameserver)
                        result.security_issues.append(f"Zone transfer allowed on {nameserver}")
                    
                except Exception as e:
                    logger.debug(f"Zone transfer test failed for {nameserver}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"Zone transfer test failed for {domain}: {str(e)}")
    
    async def _check_subdomain_takeover(self, domain: str, result: DNSSecurityResult):
        """Check for subdomain takeover vulnerabilities"""
        try:
            logger.debug(f"Checking subdomain takeover for {domain}")
            
            # Get CNAME records and check for takeover risks
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            # Check main domain and common subdomains
            subdomains_to_check = [
                domain,
                f"www.{domain}",
                f"blog.{domain}",
                f"dev.{domain}",
                f"test.{domain}",
                f"staging.{domain}",
                f"demo.{domain}"
            ]
            
            for subdomain in subdomains_to_check:
                try:
                    # Check for CNAME records
                    cname_records = resolver.resolve(subdomain, 'CNAME')
                    
                    for cname in cname_records:
                        cname_target = str(cname).rstrip('.')
                        
                        # Check if CNAME points to vulnerable services
                        for service, signatures in self.takeover_signatures.items():
                            if service in cname_target:
                                # Try to fetch the target URL to check for takeover
                                takeover_risk = await self._test_takeover_service(
                                    subdomain, cname_target, signatures
                                )
                                if takeover_risk:
                                    result.subdomain_takeover_risk.append(
                                        f"{subdomain} -> {cname_target} (vulnerable to takeover)"
                                    )
                                    result.security_issues.append(
                                        f"Subdomain takeover risk: {subdomain}"
                                    )
                
                except dns.resolver.NoAnswer:
                    # No CNAME records
                    pass
                except dns.resolver.NXDOMAIN:
                    # Subdomain doesn't exist - potential takeover if CNAME exists
                    pass
                except Exception as e:
                    logger.debug(f"Subdomain takeover check failed for {subdomain}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"Subdomain takeover check failed for {domain}: {str(e)}")
    
    async def _test_takeover_service(self, subdomain: str, cname_target: str, signatures: List[str]) -> bool:
        """Test if a service is vulnerable to subdomain takeover"""
        try:
            url = f"http://{subdomain}"
            
            # SECURITY: Validate URL before making request
            try:
                sanitized_url = validate_external_url(url)
                url = sanitized_url
            except ValueError:
                return False
            
            async with httpx.AsyncClient(timeout=10, max_redirects=3) as client:
                try:
                    response = await client.get(url)
                    response_text = response.text.lower()
                    
                    # Check for takeover signatures
                    for signature in signatures:
                        if signature.lower() in response_text:
                            return True
                            
                except Exception:
                    # If HTTP fails, try HTTPS
                    try:
                        https_url = f"https://{subdomain}"
                        response = await client.get(https_url)
                        response_text = response.text.lower()
                        
                        for signature in signatures:
                            if signature.lower() in response_text:
                                return True
                    except Exception:
                        pass
            
            return False
            
        except Exception:
            return False
    
    async def _analyze_dns_infrastructure(self, domain: str, result: DNSSecurityResult):
        """Analyze DNS infrastructure and identify providers"""
        try:
            logger.debug(f"Analyzing DNS infrastructure for {domain}")
            
            # Get SOA record for primary nameserver info
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                soa_records = resolver.resolve(domain, 'SOA')
                for soa in soa_records:
                    soa_data = str(soa).split()
                    if len(soa_data) > 0:
                        primary_ns = soa_data[0].rstrip('.')
                        result.authoritative_servers.append(primary_ns)
                        
                        # Identify DNS provider based on nameserver
                        dns_provider = self._identify_dns_provider(primary_ns)
                        if dns_provider:
                            result.dns_providers.append(dns_provider)
                            
            except Exception as e:
                logger.debug(f"SOA analysis failed for {domain}: {str(e)}")
            
            # Analyze all authoritative nameservers
            for ns in result.authoritative_servers:
                try:
                    # Check nameserver configuration
                    ns_ip = socket.gethostbyname(ns)
                    
                    # Test if nameserver responds properly
                    test_resolver = dns.resolver.Resolver()
                    test_resolver.nameservers = [ns_ip]
                    test_resolver.timeout = 5
                    
                    try:
                        test_response = test_resolver.resolve(domain, 'A')
                        # Nameserver is working properly
                    except Exception:
                        result.security_issues.append(f"Nameserver {ns} not responding properly")
                        
                except Exception as e:
                    logger.debug(f"Nameserver analysis failed for {ns}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"DNS infrastructure analysis failed for {domain}: {str(e)}")
    
    def _identify_dns_provider(self, nameserver: str) -> Optional[str]:
        """Identify DNS provider based on nameserver"""
        providers = {
            'cloudflare': ['cloudflare.com', 'ns.cloudflare.com'],
            'route53': ['awsdns', 'amazonaws.com'],
            'google': ['googledomains.com', 'google.com'],
            'azure': ['azure-dns.com', 'azure-dns.net'],
            'namecheap': ['registrar-servers.com'],
            'godaddy': ['domaincontrol.com'],
            'dnsimple': ['dnsimple.com'],
            'dnsmadeeasy': ['dnsmadeeasy.com'],
            'dyn': ['dynect.net'],
            'ultradns': ['ultradns.net']
        }
        
        nameserver_lower = nameserver.lower()
        for provider, patterns in providers.items():
            for pattern in patterns:
                if pattern in nameserver_lower:
                    return provider
        
        return None
    
    async def _check_wildcard_dns(self, domain: str, result: DNSSecurityResult):
        """Check for wildcard DNS configuration"""
        try:
            logger.debug(f"Checking wildcard DNS for {domain}")
            
            # Generate random subdomain
            import random
            import string
            random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_domain = f"{random_subdomain}.{domain}"
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                # Try to resolve random subdomain
                a_records = resolver.resolve(test_domain, 'A')
                if a_records:
                    result.wildcard_dns = True
                    result.security_issues.append("Wildcard DNS configuration detected")
                    
            except dns.resolver.NXDOMAIN:
                # Expected behavior - random subdomain should not exist
                result.wildcard_dns = False
            except Exception as e:
                logger.debug(f"Wildcard DNS test failed for {domain}: {str(e)}")
                
        except Exception as e:
            logger.debug(f"Wildcard DNS check failed for {domain}: {str(e)}")
    
    def _calculate_dns_security_score(self, result: DNSSecurityResult):
        """Calculate DNS security score (0-100)"""
        score = 100.0
        
        # DNSSEC implementation (30 points)
        if not result.dnssec_enabled:
            score -= 30
        elif not result.dnssec_valid:
            score -= 15
        
        # Zone transfer vulnerability (25 points)
        if result.zone_transfer_allowed:
            score -= 25
        
        # Subdomain takeover risks (20 points)
        takeover_penalty = min(20, len(result.subdomain_takeover_risk) * 10)
        score -= takeover_penalty
        
        # Suspicious records (15 points)
        suspicious_penalty = min(15, len(result.suspicious_records) * 5)
        score -= suspicious_penalty
        
        # Wildcard DNS (10 points)
        if result.wildcard_dns:
            score -= 10
        
        # DNS infrastructure issues (10 points)
        infrastructure_penalty = min(10, len([issue for issue in result.security_issues if 'nameserver' in issue.lower()]) * 5)
        score -= infrastructure_penalty
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.dns_security_score = score
    
    def _generate_dns_recommendations(self, result: DNSSecurityResult):
        """Generate DNS security recommendations"""
        recommendations = []
        issues = []
        
        # DNSSEC recommendations
        if not result.dnssec_enabled:
            issues.append("DNSSEC not enabled")
            recommendations.append("Enable DNSSEC to prevent DNS spoofing and cache poisoning attacks")
        elif not result.dnssec_valid:
            issues.append("DNSSEC validation errors")
            recommendations.append("Fix DNSSEC configuration errors and ensure proper key signing")
        
        # Zone transfer recommendations
        if result.zone_transfer_allowed:
            issues.append("Zone transfer allowed")
            recommendations.append("Disable zone transfers to unauthorized hosts")
            recommendations.append("Restrict AXFR requests to authorized secondary nameservers only")
        
        # Subdomain takeover recommendations
        if result.subdomain_takeover_risk:
            issues.append("Subdomain takeover vulnerabilities")
            recommendations.append("Remove or update CNAME records pointing to inactive services")
            recommendations.append("Monitor subdomains for takeover attempts")
            recommendations.append("Implement subdomain monitoring and alerting")
        
        # Suspicious records recommendations
        if result.suspicious_records:
            issues.append("Suspicious DNS records detected")
            recommendations.append("Review and validate all DNS records")
            recommendations.append("Remove any unauthorized or suspicious DNS entries")
        
        # Wildcard DNS recommendations
        if result.wildcard_dns:
            issues.append("Wildcard DNS configured")
            recommendations.append("Consider disabling wildcard DNS if not required")
            recommendations.append("Monitor for subdomain abuse if wildcard DNS is necessary")
        
        # General recommendations
        if result.dns_security_score < 70:
            recommendations.append("Implement DNS monitoring and logging")
            recommendations.append("Use DNS filtering and threat intelligence")
            recommendations.append("Consider using managed DNS services with security features")
        
        # Infrastructure recommendations
        if len(result.authoritative_servers) < 2:
            recommendations.append("Configure multiple authoritative nameservers for redundancy")
        
        if not result.dns_providers:
            recommendations.append("Consider using managed DNS services for better security")
        
        result.security_issues.extend(issues)
        result.recommendations = recommendations 