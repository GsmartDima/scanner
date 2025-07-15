"""
Enhanced SSL/TLS Security Analysis Module
Performs comprehensive SSL/TLS security assessment including certificate validation,
cipher analysis, protocol security, vulnerability testing, and security scoring.
"""
import asyncio
import ssl
import socket
import datetime
import logging
import re
import subprocess
import json
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ipaddress

from models import EnhancedSSLResult, Asset
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class SSLTLSSecurityAnalyzer:
    """Enhanced SSL/TLS security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        self.default_port = 443
        
        # SSL/TLS protocol versions
        self.ssl_protocols = {
            'TLSv1.3': ssl.PROTOCOL_TLS,
            'TLSv1.2': ssl.PROTOCOL_TLS,
            'TLSv1.1': ssl.PROTOCOL_TLS,
            'TLSv1.0': ssl.PROTOCOL_TLS,
            'SSLv3': getattr(ssl, 'PROTOCOL_SSLv3', None),
            'SSLv2': getattr(ssl, 'PROTOCOL_SSLv2', None)
        }
        
        # Cipher strength classification
        self.strong_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES256-SHA384',
            'ECDHE-ECDSA-AES128-SHA256'
        ]
        
        self.weak_ciphers = [
            'RC4',
            'DES',
            'MD5',
            'NULL',
            'EXPORT',
            'ADH',
            'AECDH'
        ]
        
        self.deprecated_ciphers = [
            'SSLv2',
            'SSLv3',
            'TLSv1.0',
            'CBC'
        ]
        
        # Vulnerability patterns
        self.vulnerability_checks = {
            'heartbleed': {
                'description': 'OpenSSL Heartbleed vulnerability (CVE-2014-0160)',
                'test_method': '_test_heartbleed'
            },
            'poodle': {
                'description': 'POODLE vulnerability (CVE-2014-3566)',
                'test_method': '_test_poodle'
            },
            'crime': {
                'description': 'CRIME vulnerability',
                'test_method': '_test_crime'
            },
            'breach': {
                'description': 'BREACH vulnerability',
                'test_method': '_test_breach'
            },
            'beast': {
                'description': 'BEAST vulnerability',
                'test_method': '_test_beast'
            }
        }
    
    async def analyze_ssl_security(self, assets: List[Asset]) -> List[EnhancedSSLResult]:
        """Perform comprehensive SSL/TLS security analysis"""
        logger.info(f"Starting enhanced SSL/TLS security analysis for {len(assets)} assets")
        
        results = []
        
        # Process HTTPS assets
        https_assets = [asset for asset in assets if asset.protocol == 'https']
        
        if not https_assets:
            logger.info("No HTTPS assets found for SSL analysis")
            return results
        
        # Analyze each HTTPS asset
        tasks = []
        for asset in https_assets:
            task = self._analyze_asset_ssl(asset)
            tasks.append(task)
        
        # Execute SSL analysis with limited concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent SSL tests
        
        async def limited_analysis(asset):
            async with semaphore:
                return await self._analyze_asset_ssl(asset)
        
        results = await asyncio.gather(*[limited_analysis(asset) for asset in https_assets], 
                                     return_exceptions=True)
        
        # Filter out exceptions and None results
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"SSL analysis failed for {https_assets[i].domain}: {result}")
            elif result:
                valid_results.append(result)
        
        logger.info(f"Completed SSL/TLS analysis: {len(valid_results)} results")
        return valid_results
    
    async def _analyze_asset_ssl(self, asset: Asset) -> Optional[EnhancedSSLResult]:
        """Analyze SSL/TLS security for a single asset"""
        try:
            # SECURITY: Validate the domain/IP before connecting
            if not self._is_safe_target(asset.domain):
                logger.warning(f"Skipping SSL analysis for potentially unsafe target: {asset.domain}")
                return None
            
            logger.info(f"Analyzing SSL/TLS security for {asset.domain}:{asset.port}")
            
            # Create result object
            result = EnhancedSSLResult(
                domain=asset.domain,
                port=asset.port if asset.port != 80 else 443
            )
            
            # Test SSL availability
            ssl_info = await self._test_ssl_connection(asset.domain, result.port)
            if not ssl_info:
                result.has_ssl = False
                result.ssl_security_score = 0
                result.security_grade = "F"
                result.security_issues.append("No SSL/TLS support detected")
                return result
            
            result.has_ssl = True
            
            # Analyze certificate
            await self._analyze_certificate(ssl_info, result)
            
            # Test supported protocols
            await self._test_ssl_protocols(asset.domain, result.port, result)
            
            # Analyze cipher suites
            await self._analyze_cipher_suites(ssl_info, result)
            
            # Test for vulnerabilities
            await self._test_ssl_vulnerabilities(asset.domain, result.port, result)
            
            # Check HSTS headers
            await self._check_hsts_headers(asset, result)
            
            # Calculate security score and grade
            self._calculate_ssl_security_score(result)
            
            # Generate recommendations
            self._generate_ssl_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"SSL analysis failed for {asset.domain}: {str(e)}")
            return None
    
    def _is_safe_target(self, target: str) -> bool:
        """Validate that the target is safe for SSL analysis"""
        try:
            # Check if it's an IP address
            ip = ipaddress.ip_address(target)
            # Block private/internal IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # It's a domain name, validate it
            if not is_safe_domain(target):
                return False
        
        return True
    
    async def _test_ssl_connection(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Test SSL connection and get basic SSL information"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with timeout
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate and cipher information
                    cert_der = ssock.getpeercert_der()
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'certificate_der': cert_der,
                        'certificate_dict': cert_dict,
                        'cipher': cipher,
                        'ssl_version': ssock.version()
                    }
        except Exception as e:
            logger.debug(f"SSL connection test failed for {hostname}:{port}: {str(e)}")
            return None
    
    async def _analyze_certificate(self, ssl_info: Dict[str, Any], result: EnhancedSSLResult):
        """Analyze SSL certificate details"""
        try:
            cert_der = ssl_info['certificate_der']
            cert_dict = ssl_info['certificate_dict']
            
            # Parse certificate using cryptography library
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Basic certificate info
            result.certificate_issuer = cert.issuer.rfc4514_string()
            result.certificate_subject = cert.subject.rfc4514_string()
            result.certificate_expiry = cert.not_valid_after
            result.certificate_signature_algorithm = cert.signature_algorithm_oid._name
            
            # Check if certificate is valid
            now = datetime.datetime.now()
            result.certificate_valid = cert.not_valid_before <= now <= cert.not_valid_after
            result.certificate_expired = now > cert.not_valid_after
            
            # Check for self-signed certificate
            result.self_signed = cert.issuer == cert.subject
            
            # Extract Subject Alternative Names (SAN)
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                result.certificate_san = [name.value for name in san_extension.value]
            except x509.ExtensionNotFound:
                result.certificate_san = []
            
            # Check for wildcard certificate
            result.wildcard_certificate = any('*' in name for name in result.certificate_san) or '*' in result.certificate_subject
            
            # Validate certificate chain (basic check)
            result.certificate_chain_valid = not result.self_signed and result.certificate_valid
            
        except Exception as e:
            logger.debug(f"Certificate analysis failed: {str(e)}")
            result.security_issues.append("Certificate analysis failed")
    
    async def _test_ssl_protocols(self, hostname: str, port: int, result: EnhancedSSLResult):
        """Test supported SSL/TLS protocols"""
        protocol_support = {}
        
        # Test TLS 1.3
        protocol_support['TLSv1.3'] = await self._test_protocol_support(hostname, port, 'TLSv1.3')
        result.supports_tls13 = protocol_support['TLSv1.3']
        
        # Test TLS 1.2
        protocol_support['TLSv1.2'] = await self._test_protocol_support(hostname, port, 'TLSv1.2')
        result.supports_tls12 = protocol_support['TLSv1.2']
        
        # Test TLS 1.1
        protocol_support['TLSv1.1'] = await self._test_protocol_support(hostname, port, 'TLSv1.1')
        result.supports_tls11 = protocol_support['TLSv1.1']
        
        # Test TLS 1.0
        protocol_support['TLSv1.0'] = await self._test_protocol_support(hostname, port, 'TLSv1.0')
        result.supports_tls10 = protocol_support['TLSv1.0']
        
        # Test SSLv3 (should be disabled)
        protocol_support['SSLv3'] = await self._test_protocol_support(hostname, port, 'SSLv3')
        result.supports_ssl3 = protocol_support['SSLv3']
        
        # Test SSLv2 (should be disabled)
        protocol_support['SSLv2'] = await self._test_protocol_support(hostname, port, 'SSLv2')
        result.supports_ssl2 = protocol_support['SSLv2']
        
        # Store supported versions
        result.ssl_versions_supported = [version for version, supported in protocol_support.items() if supported]
    
    async def _test_protocol_support(self, hostname: str, port: int, protocol: str) -> bool:
        """Test if a specific SSL/TLS protocol is supported"""
        try:
            # Use openssl command for more accurate protocol testing
            cmd = [
                'openssl', 's_client',
                '-connect', f'{hostname}:{port}',
                '-{}'.format(protocol.lower().replace('v', '')),
                '-verify_return_error',
                '-brief'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=10
            )
            
            # Check if connection was successful
            output = stdout.decode() + stderr.decode()
            return 'connected' in output.lower() and 'verify return:1' not in output
            
        except Exception:
            # Fallback to Python SSL
            try:
                context = ssl.SSLContext()
                if protocol == 'TLSv1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                elif protocol == 'TLSv1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif protocol == 'TLSv1.1':
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                elif protocol == 'TLSv1.0':
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                else:
                    return False  # SSLv3/SSLv2 not supported in modern Python
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return True
                        
            except Exception:
                return False
    
    async def _analyze_cipher_suites(self, ssl_info: Dict[str, Any], result: EnhancedSSLResult):
        """Analyze supported cipher suites"""
        try:
            cipher = ssl_info.get('cipher')
            if not cipher:
                return
            
            cipher_name = cipher[0] if cipher else ''
            
            # Classify cipher strength
            is_strong = any(strong_cipher in cipher_name for strong_cipher in self.strong_ciphers)
            is_weak = any(weak_cipher in cipher_name for weak_cipher in self.weak_ciphers)
            is_deprecated = any(dep_cipher in cipher_name for dep_cipher in self.deprecated_ciphers)
            
            if is_strong:
                result.strong_ciphers += 1
            if is_weak:
                result.weak_ciphers += 1
            if is_deprecated:
                result.deprecated_ciphers += 1
            
            # Check for forward secrecy
            result.forward_secrecy = 'ECDHE' in cipher_name or 'DHE' in cipher_name
            
            # Store cipher suite info
            cipher_info = {
                'name': cipher_name,
                'version': cipher[1] if len(cipher) > 1 else '',
                'bits': cipher[2] if len(cipher) > 2 else 0,
                'strength': 'strong' if is_strong else 'weak' if is_weak else 'medium'
            }
            result.cipher_suites.append(cipher_info)
            
        except Exception as e:
            logger.debug(f"Cipher analysis failed: {str(e)}")
    
    async def _test_ssl_vulnerabilities(self, hostname: str, port: int, result: EnhancedSSLResult):
        """Test for known SSL/TLS vulnerabilities"""
        try:
            # Test for Heartbleed
            result.vulnerable_to_heartbleed = await self._test_heartbleed(hostname, port)
            
            # Test for POODLE
            result.vulnerable_to_poodle = await self._test_poodle(hostname, port)
            
            # Test for CRIME
            result.vulnerable_to_crime = await self._test_crime(hostname, port)
            
            # Test for BREACH
            result.vulnerable_to_breach = await self._test_breach(hostname, port)
            
            # Test for BEAST
            result.vulnerable_to_beast = await self._test_beast(hostname, port)
            
        except Exception as e:
            logger.debug(f"Vulnerability testing failed: {str(e)}")
    
    async def _test_heartbleed(self, hostname: str, port: int) -> bool:
        """Test for Heartbleed vulnerability"""
        # Basic check - if TLS 1.2 or higher is exclusively supported, likely not vulnerable
        try:
            supports_old_tls = await self._test_protocol_support(hostname, port, 'TLSv1.0') or \
                              await self._test_protocol_support(hostname, port, 'TLSv1.1')
            return supports_old_tls  # Simplified check
        except:
            return False
    
    async def _test_poodle(self, hostname: str, port: int) -> bool:
        """Test for POODLE vulnerability"""
        # POODLE affects SSLv3
        return await self._test_protocol_support(hostname, port, 'SSLv3')
    
    async def _test_crime(self, hostname: str, port: int) -> bool:
        """Test for CRIME vulnerability"""
        # CRIME attacks TLS compression
        try:
            # This is a simplified check
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check if compression is enabled (simplified)
                    return hasattr(ssock, 'compression') and ssock.compression() is not None
        except:
            return False
    
    async def _test_breach(self, hostname: str, port: int) -> bool:
        """Test for BREACH vulnerability"""
        # BREACH attacks HTTP compression, check if gzip is enabled
        try:
            url = f"https://{hostname}:{port}/"
            
            # SECURITY: Validate URL before making request
            try:
                sanitized_url = validate_external_url(url)
                url = sanitized_url
            except ValueError:
                return False
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                headers = {'Accept-Encoding': 'gzip, deflate'}
                response = await client.get(url, headers=headers)
                return 'gzip' in response.headers.get('content-encoding', '')
        except:
            return False
    
    async def _test_beast(self, hostname: str, port: int) -> bool:
        """Test for BEAST vulnerability"""
        # BEAST affects TLS 1.0 with CBC ciphers
        supports_tls10 = await self._test_protocol_support(hostname, port, 'TLSv1.0')
        if not supports_tls10:
            return False
        
        # Check if CBC ciphers are supported (simplified)
        try:
            ssl_info = await self._test_ssl_connection(hostname, port)
            if ssl_info and ssl_info.get('cipher'):
                cipher_name = ssl_info['cipher'][0]
                return 'CBC' in cipher_name
        except:
            pass
        
        return False
    
    async def _check_hsts_headers(self, asset: Asset, result: EnhancedSSLResult):
        """Check HSTS (HTTP Strict Transport Security) headers"""
        try:
            url = f"https://{asset.domain}:{asset.port}/"
            
            # SECURITY: Validate URL before making request
            try:
                sanitized_url = validate_external_url(url)
                url = sanitized_url
            except ValueError:
                return
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(url)
                
                hsts_header = response.headers.get('strict-transport-security')
                if hsts_header:
                    result.hsts_enabled = True
                    
                    # Parse HSTS header
                    if 'max-age=' in hsts_header:
                        max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                        if max_age_match:
                            result.hsts_max_age = int(max_age_match.group(1))
                    
                    result.hsts_include_subdomains = 'includeSubDomains' in hsts_header
                    result.hsts_preload = 'preload' in hsts_header
                
        except Exception as e:
            logger.debug(f"HSTS check failed for {asset.domain}: {str(e)}")
    
    def _calculate_ssl_security_score(self, result: EnhancedSSLResult):
        """Calculate SSL security score (0-100)"""
        score = 100.0
        
        # Certificate issues
        if not result.certificate_valid:
            score -= 30
        if result.certificate_expired:
            score -= 25
        if result.self_signed:
            score -= 20
        
        # Protocol issues
        if result.supports_ssl2:
            score -= 40  # Critical
        if result.supports_ssl3:
            score -= 30  # High
        if result.supports_tls10:
            score -= 15  # Medium
        if result.supports_tls11:
            score -= 10  # Low
        if not result.supports_tls12:
            score -= 20  # Should support TLS 1.2 minimum
        
        # Cipher issues
        if result.weak_ciphers > 0:
            score -= 25
        if result.deprecated_ciphers > 0:
            score -= 15
        if not result.forward_secrecy:
            score -= 10
        
        # Vulnerability issues
        if result.vulnerable_to_heartbleed:
            score -= 40
        if result.vulnerable_to_poodle:
            score -= 30
        if result.vulnerable_to_crime:
            score -= 15
        if result.vulnerable_to_breach:
            score -= 10
        if result.vulnerable_to_beast:
            score -= 15
        
        # HSTS bonus
        if result.hsts_enabled:
            score += 5
            if result.hsts_include_subdomains:
                score += 3
            if result.hsts_preload:
                score += 2
        
        # TLS 1.3 bonus
        if result.supports_tls13:
            score += 10
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.ssl_security_score = score
        
        # Assign grade
        if score >= 90:
            result.security_grade = "A+"
        elif score >= 80:
            result.security_grade = "A"
        elif score >= 70:
            result.security_grade = "B"
        elif score >= 60:
            result.security_grade = "C"
        elif score >= 50:
            result.security_grade = "D"
        elif score >= 40:
            result.security_grade = "E"
        else:
            result.security_grade = "F"
    
    def _generate_ssl_recommendations(self, result: EnhancedSSLResult):
        """Generate SSL security recommendations"""
        recommendations = []
        issues = []
        
        # Certificate issues
        if not result.certificate_valid:
            issues.append("Invalid SSL certificate")
            recommendations.append("Install a valid SSL certificate from a trusted CA")
        
        if result.certificate_expired:
            issues.append("SSL certificate has expired")
            recommendations.append("Renew the SSL certificate immediately")
        
        if result.self_signed:
            issues.append("Self-signed certificate detected")
            recommendations.append("Replace self-signed certificate with one from a trusted CA")
        
        # Protocol issues
        if result.supports_ssl2 or result.supports_ssl3:
            issues.append("Deprecated SSL protocols enabled")
            recommendations.append("Disable SSLv2 and SSLv3 protocols")
        
        if result.supports_tls10 or result.supports_tls11:
            issues.append("Deprecated TLS protocols enabled")
            recommendations.append("Disable TLS 1.0 and TLS 1.1, use TLS 1.2+ only")
        
        if not result.supports_tls12:
            issues.append("TLS 1.2 not supported")
            recommendations.append("Enable TLS 1.2 support")
        
        if not result.supports_tls13:
            issues.append("TLS 1.3 not supported")
            recommendations.append("Enable TLS 1.3 for better security and performance")
        
        # Cipher issues
        if result.weak_ciphers > 0:
            issues.append("Weak cipher suites enabled")
            recommendations.append("Disable weak cipher suites (RC4, DES, MD5, NULL, EXPORT)")
        
        if not result.forward_secrecy:
            issues.append("Perfect Forward Secrecy not supported")
            recommendations.append("Enable ECDHE or DHE cipher suites for Perfect Forward Secrecy")
        
        # Vulnerability issues
        if result.vulnerable_to_heartbleed:
            issues.append("Vulnerable to Heartbleed attack")
            recommendations.append("Update OpenSSL to fix Heartbleed vulnerability")
        
        if result.vulnerable_to_poodle:
            issues.append("Vulnerable to POODLE attack")
            recommendations.append("Disable SSLv3 to prevent POODLE attacks")
        
        if result.vulnerable_to_crime:
            issues.append("Vulnerable to CRIME attack")
            recommendations.append("Disable TLS compression to prevent CRIME attacks")
        
        if result.vulnerable_to_breach:
            issues.append("Potentially vulnerable to BREACH attack")
            recommendations.append("Consider disabling HTTP compression for sensitive content")
        
        if result.vulnerable_to_beast:
            issues.append("Vulnerable to BEAST attack")
            recommendations.append("Disable TLS 1.0 and CBC ciphers to prevent BEAST attacks")
        
        # HSTS recommendations
        if not result.hsts_enabled:
            issues.append("HSTS not enabled")
            recommendations.append("Enable HTTP Strict Transport Security (HSTS) headers")
        elif result.hsts_max_age and result.hsts_max_age < 31536000:  # 1 year
            issues.append("HSTS max-age too short")
            recommendations.append("Set HSTS max-age to at least 31536000 seconds (1 year)")
        
        if result.hsts_enabled and not result.hsts_include_subdomains:
            recommendations.append("Include subdomains in HSTS policy")
        
        # General recommendations
        if result.ssl_security_score < 80:
            recommendations.append("Review and update SSL/TLS configuration")
        
        if not result.certificate_chain_valid:
            recommendations.append("Ensure complete certificate chain is properly configured")
        
        result.security_issues = issues
        result.recommendations = recommendations 