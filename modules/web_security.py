"""
Enhanced Web Application Security Analysis Module
Performs comprehensive web application security testing including OWASP Top 10,
XSS detection, SQL injection testing, directory traversal, and security headers analysis.
"""
import asyncio
import re
import urllib.parse
import random
import string
import logging
from typing import List, Dict, Any, Optional, Tuple
import httpx
from bs4 import BeautifulSoup
import base64
import subprocess
import json

from models import WebSecurityResult, Asset
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class WebSecurityAnalyzer:
    """Enhanced web application security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        self.max_redirects = 5
        
        # WAF detection configuration
        self.waf_detection_enabled = True
        self.waf_timeout = 30
        
        # XSS test payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'>><script>alert('XSS')</script>",
            '"><script>alert("XSS")</script>',
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "';alert('XSS');//",
            '";alert("XSS");//',
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "\"><img src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'"
        ]
        
        # SQL injection test payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1 limit 1 -- -+",
            "' or 1=1 limit 1 offset 1 -- -+",
            "' UNION SELECT 1--",
            "' UNION SELECT NULL--",
            "' UNION ALL SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        # Directory traversal payloads
        self.directory_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "expect://whoami"
        ]
        
        # Common sensitive files to check
        self.sensitive_files = [
            ".env",
            ".git/config",
            ".svn/entries",
            "config.php",
            "database.php",
            "wp-config.php",
            "web.config",
            "app.config",
            "settings.py",
            "config.json",
            "config.xml",
            "phpinfo.php",
            "info.php",
            "test.php",
            "admin.php",
            "backup.sql",
            "dump.sql",
            "robots.txt",
            "sitemap.xml",
            ".htaccess",
            ".htpasswd",
            "crossdomain.xml",
            "clientaccesspolicy.xml"
        ]
        
        # Security headers to check
        self.security_headers = {
            'x-frame-options': {
                'description': 'Prevents clickjacking attacks',
                'expected_values': ['DENY', 'SAMEORIGIN'],
                'severity': 'MEDIUM'
            },
            'x-content-type-options': {
                'description': 'Prevents MIME type sniffing',
                'expected_values': ['nosniff'],
                'severity': 'MEDIUM'
            },
            'x-xss-protection': {
                'description': 'Enables XSS filtering in browsers',
                'expected_values': ['1; mode=block'],
                'severity': 'LOW'
            },
            'strict-transport-security': {
                'description': 'Enforces HTTPS connections',
                'expected_values': [],  # Any value is good
                'severity': 'HIGH'
            },
            'content-security-policy': {
                'description': 'Prevents XSS and data injection attacks',
                'expected_values': [],  # Any policy is better than none
                'severity': 'HIGH'
            },
            'referrer-policy': {
                'description': 'Controls referrer information',
                'expected_values': ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer'],
                'severity': 'LOW'
            },
            'permissions-policy': {
                'description': 'Controls browser features',
                'expected_values': [],
                'severity': 'LOW'
            }
        }
    
    async def analyze_web_security(self, assets: List[Asset]) -> List[WebSecurityResult]:
        """Perform comprehensive web application security analysis"""
        logger.info(f"Starting enhanced web security analysis for {len(assets)} assets")
        
        results = []
        
        # Process HTTP and HTTPS assets
        web_assets = [asset for asset in assets if asset.protocol in ['http', 'https']]
        
        if not web_assets:
            logger.info("No web assets found for security analysis")
            return results
        
        # Analyze each web asset with limited concurrency
        semaphore = asyncio.Semaphore(3)  # Limit concurrent web tests
        
        async def limited_analysis(asset):
            async with semaphore:
                return await self._analyze_asset_web_security(asset)
        
        results = await asyncio.gather(*[limited_analysis(asset) for asset in web_assets], 
                                     return_exceptions=True)
        
        # Filter out exceptions and None results
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Web security analysis failed for {web_assets[i].domain}: {result}")
            elif result:
                valid_results.append(result)
        
        logger.info(f"Completed web security analysis: {len(valid_results)} results")
        return valid_results
    
    async def _analyze_asset_web_security(self, asset: Asset) -> Optional[WebSecurityResult]:
        """Analyze web security for a single asset"""
        try:
            # SECURITY: Validate the target before testing
            if not is_safe_domain(asset.domain):
                logger.warning(f"Skipping web security analysis for potentially unsafe target: {asset.domain}")
                return None
            
            url = f"{asset.protocol}://{asset.domain}:{asset.port}/"
            
            # SECURITY: Validate URL before making requests
            try:
                sanitized_url = validate_external_url(url)
                url = sanitized_url
            except ValueError as e:
                logger.warning(f"Skipping unsafe URL {url}: {e}")
                return None
            
            logger.info(f"Analyzing web security for {url}")
            
            # Create result object
            result = WebSecurityResult(
                domain=asset.domain,
                url=url
            )
            
            # Basic HTTP client setup
            async with httpx.AsyncClient(
                timeout=self.timeout,
                max_redirects=self.max_redirects,
                verify=False  # We're doing security testing, so ignore SSL verification
            ) as client:
                
                # Get initial response
                try:
                    response = await client.get(url)
                    result.security_headers = dict(response.headers)
                except Exception as e:
                    logger.debug(f"Failed to fetch {url}: {e}")
                    return None
                
                # Analyze security headers
                await self._analyze_security_headers(response, result)
                
                # Analyze Content Security Policy
                await self._analyze_csp(response, result)
                
                # Test for XSS vulnerabilities
                await self._test_xss_vulnerabilities(client, url, result)
                
                # Test for SQL injection vulnerabilities
                await self._test_sqli_vulnerabilities(client, url, result)
                
                # Test for directory traversal
                await self._test_directory_traversal(client, url, result)
                
                # Check for information disclosure
                await self._check_information_disclosure(client, url, result)
                
                # Test authentication and session management
                await self._test_authentication_security(client, url, result)
                
                # Check for file upload vulnerabilities
                await self._test_file_upload_security(client, url, result)
                
                # Perform OWASP Top 10 assessment
                await self._assess_owasp_top10(client, url, response, result)
                
                # Check for CMS/framework specific vulnerabilities
                await self._check_cms_vulnerabilities(client, url, asset, result)
                
                # Check for WAF protection
                await self._check_waf_protection(url, result)
                
                # Calculate security score and grade
                self._calculate_web_security_score(result)
                
                # Generate recommendations
                self._generate_web_security_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Web security analysis failed for {asset.domain}: {str(e)}")
            return None
    
    async def _analyze_security_headers(self, response: httpx.Response, result: WebSecurityResult):
        """Analyze HTTP security headers"""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                result.missing_headers.append(header_name)
                result.security_issues.append(f"Missing {header_name} header")
            else:
                header_value = headers[header_name]
                
                # Validate header values
                if header_info['expected_values'] and header_value not in header_info['expected_values']:
                    # Special handling for some headers
                    if header_name == 'strict-transport-security':
                        if 'max-age=' not in header_value:
                            result.insecure_headers.append(f"{header_name}: missing max-age")
                    elif header_name == 'content-security-policy':
                        if 'unsafe-inline' in header_value:
                            result.insecure_headers.append(f"{header_name}: allows unsafe-inline")
                        if 'unsafe-eval' in header_value:
                            result.insecure_headers.append(f"{header_name}: allows unsafe-eval")
        
        # Check for information disclosure headers
        disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for header in disclosure_headers:
            if header in headers:
                result.information_disclosure.append(f"Server information disclosed: {header}")
                result.server_info_disclosed = True
    
    async def _analyze_csp(self, response: httpx.Response, result: WebSecurityResult):
        """Analyze Content Security Policy"""
        csp_header = response.headers.get('content-security-policy')
        if csp_header:
            result.csp_enabled = True
            result.csp_policies = [csp_header]
            
            # Check for unsafe directives
            if 'unsafe-inline' in csp_header:
                result.csp_unsafe_inline = True
                result.csp_issues.append("CSP allows 'unsafe-inline'")
            
            if 'unsafe-eval' in csp_header:
                result.csp_unsafe_eval = True
                result.csp_issues.append("CSP allows 'unsafe-eval'")
            
            if '*' in csp_header:
                result.csp_issues.append("CSP uses wildcard (*) directive")
        else:
            result.csp_enabled = False
            result.security_issues.append("Content Security Policy not implemented")
    
    async def _test_xss_vulnerabilities(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Test for Cross-Site Scripting vulnerabilities"""
        logger.debug(f"Testing XSS vulnerabilities for {base_url}")
        
        # Test GET parameter XSS
        test_params = ['q', 'search', 'query', 'name', 'input', 'data', 'test']
        
        for param in test_params:
            for i, payload in enumerate(self.xss_payloads[:5]):  # Limit to first 5 payloads
                try:
                    # Test GET parameter
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    response = await client.get(test_url)
                    
                    if payload in response.text:
                        result.xss_vulnerable = True
                        result.xss_payloads_successful.append(f"GET {param}: {payload}")
                        result.security_issues.append(f"XSS vulnerability found in GET parameter '{param}'")
                        break  # Found vulnerability, move to next parameter
                    
                    result.xss_vectors_tested += 1
                    
                except Exception as e:
                    logger.debug(f"XSS test failed for {test_url}: {e}")
            
            # Delay between tests to be respectful
            await asyncio.sleep(0.5)
    
    async def _test_sqli_vulnerabilities(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Test for SQL injection vulnerabilities"""
        logger.debug(f"Testing SQL injection vulnerabilities for {base_url}")
        
        # Test common parameter names
        test_params = ['id', 'user', 'username', 'login', 'search', 'query', 'page']
        
        for param in test_params:
            for i, payload in enumerate(self.sqli_payloads[:5]):  # Limit to first 5 payloads
                try:
                    # Test GET parameter
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    response = await client.get(test_url)
                    
                    # Look for SQL error indicators
                    sql_errors = [
                        'mysql_fetch',
                        'ORA-',
                        'Microsoft OLE DB',
                        'ODBC SQL',
                        'PostgreSQL',
                        'Warning: mysql',
                        'MySQLSyntaxErrorException',
                        'valid MySQL result',
                        'Unclosed quotation mark',
                        'OLE DB',
                        'SQL syntax',
                        'SQLSTATE',
                        'SQLException'
                    ]
                    
                    response_text = response.text.lower()
                    for error in sql_errors:
                        if error.lower() in response_text:
                            result.sqli_vulnerable = True
                            result.sqli_payloads_successful.append(f"GET {param}: {payload}")
                            result.security_issues.append(f"SQL injection vulnerability found in GET parameter '{param}'")
                            break
                    
                    result.sqli_vectors_tested += 1
                    
                except Exception as e:
                    logger.debug(f"SQLi test failed for {test_url}: {e}")
            
            # Delay between tests
            await asyncio.sleep(0.5)
    
    async def _test_directory_traversal(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Test for directory traversal vulnerabilities"""
        logger.debug(f"Testing directory traversal for {base_url}")
        
        # Test common parameters that might be vulnerable
        test_params = ['file', 'path', 'page', 'include', 'doc', 'template']
        
        for param in test_params:
            for payload in self.directory_traversal_payloads[:3]:  # Limit tests
                try:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    response = await client.get(test_url)
                    
                    # Look for indicators of successful directory traversal
                    indicators = [
                        'root:x:0:0:',  # Linux /etc/passwd
                        '[boot loader]',  # Windows boot.ini
                        '127.0.0.1',  # hosts file
                        '# localhost',  # hosts file comment
                        'dns.msft'  # Windows hosts file
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in indicators:
                        if indicator.lower() in response_text:
                            result.directory_traversal_vulnerable = True
                            result.directory_traversal_paths.append(f"GET {param}: {payload}")
                            result.security_issues.append(f"Directory traversal vulnerability found in parameter '{param}'")
                            break
                    
                except Exception as e:
                    logger.debug(f"Directory traversal test failed for {test_url}: {e}")
            
            await asyncio.sleep(0.5)
    
    async def _check_information_disclosure(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Check for information disclosure vulnerabilities"""
        logger.debug(f"Checking information disclosure for {base_url}")
        
        # Test for sensitive files
        for sensitive_file in self.sensitive_files[:10]:  # Limit to first 10
            try:
                test_url = f"{base_url.rstrip('/')}/{sensitive_file}"
                response = await client.get(test_url)
                
                if response.status_code == 200:
                    result.information_disclosure.append(f"Sensitive file exposed: {sensitive_file}")
                    
                    # Check if it's a directory listing
                    if 'index of' in response.text.lower():
                        result.directory_listing_enabled = True
                        result.security_issues.append("Directory listing enabled")
                
            except Exception as e:
                logger.debug(f"Info disclosure test failed for {test_url}: {e}")
            
            await asyncio.sleep(0.1)
    
    async def _test_authentication_security(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Test authentication and session management security"""
        logger.debug(f"Testing authentication security for {base_url}")
        
        try:
            # Check for common admin/login pages
            admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/auth']
            
            for path in admin_paths:
                try:
                    test_url = f"{base_url.rstrip('/')}{path}"
                    response = await client.get(test_url)
                    
                    if response.status_code == 200:
                        # Check for weak authentication indicators
                        if 'password' in response.text.lower() and 'username' in response.text.lower():
                            # Look for common issues
                            if 'admin' in response.text.lower() and 'admin' in response.text.lower():
                                result.weak_authentication = True
                                result.security_issues.append("Potential default credentials on admin page")
                            
                            # Check for missing CSRF protection
                            if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                                result.insecure_session_management = True
                                result.security_issues.append("Login form missing CSRF protection")
                
                except Exception as e:
                    logger.debug(f"Auth test failed for {test_url}: {e}")
                
                await asyncio.sleep(0.2)
            
        except Exception as e:
            logger.debug(f"Authentication security test failed: {e}")
    
    async def _test_file_upload_security(self, client: httpx.AsyncClient, base_url: str, result: WebSecurityResult):
        """Test for file upload vulnerabilities"""
        logger.debug(f"Testing file upload security for {base_url}")
        
        try:
            # Look for file upload forms
            response = await client.get(base_url)
            
            if 'type="file"' in response.text:
                result.file_upload_issues.append("File upload form detected")
                
                # Parse forms to find upload endpoints
                soup = BeautifulSoup(response.text, 'html.parser')
                upload_forms = soup.find_all('form')
                
                for form in upload_forms:
                    if form.find('input', {'type': 'file'}):
                        # Check if form has proper security measures
                        if not form.get('enctype') == 'multipart/form-data':
                            result.file_upload_issues.append("Upload form missing proper enctype")
                        
                        # Check for CSRF protection
                        if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                            result.file_upload_issues.append("Upload form missing CSRF protection")
                            result.unrestricted_file_upload = True
        
        except Exception as e:
            logger.debug(f"File upload test failed: {e}")
    
    async def _assess_owasp_top10(self, client: httpx.AsyncClient, base_url: str, response: httpx.Response, result: WebSecurityResult):
        """Assess against OWASP Top 10 vulnerabilities"""
        owasp_assessment = {}
        
        # A01:2021 – Broken Access Control
        owasp_assessment['A01_Broken_Access_Control'] = {
            'vulnerable': result.weak_authentication or result.directory_listing_enabled,
            'details': []
        }
        if result.weak_authentication:
            owasp_assessment['A01_Broken_Access_Control']['details'].append("Weak authentication detected")
        if result.directory_listing_enabled:
            owasp_assessment['A01_Broken_Access_Control']['details'].append("Directory listing enabled")
        
        # A02:2021 – Cryptographic Failures
        is_http = base_url.startswith('http://')
        missing_hsts = 'strict-transport-security' not in [h.lower() for h in response.headers.keys()]
        owasp_assessment['A02_Cryptographic_Failures'] = {
            'vulnerable': is_http or missing_hsts,
            'details': []
        }
        if is_http:
            owasp_assessment['A02_Cryptographic_Failures']['details'].append("Using HTTP instead of HTTPS")
        if missing_hsts:
            owasp_assessment['A02_Cryptographic_Failures']['details'].append("Missing HSTS header")
        
        # A03:2021 – Injection
        owasp_assessment['A03_Injection'] = {
            'vulnerable': result.xss_vulnerable or result.sqli_vulnerable or result.directory_traversal_vulnerable,
            'details': []
        }
        if result.xss_vulnerable:
            owasp_assessment['A03_Injection']['details'].append("XSS vulnerability detected")
        if result.sqli_vulnerable:
            owasp_assessment['A03_Injection']['details'].append("SQL injection vulnerability detected")
        if result.directory_traversal_vulnerable:
            owasp_assessment['A03_Injection']['details'].append("Directory traversal vulnerability detected")
        
        # A04:2021 – Insecure Design
        owasp_assessment['A04_Insecure_Design'] = {
            'vulnerable': not result.csp_enabled or result.csp_unsafe_inline,
            'details': []
        }
        if not result.csp_enabled:
            owasp_assessment['A04_Insecure_Design']['details'].append("No Content Security Policy")
        if result.csp_unsafe_inline:
            owasp_assessment['A04_Insecure_Design']['details'].append("CSP allows unsafe-inline")
        
        # A05:2021 – Security Misconfiguration
        has_info_disclosure = len(result.information_disclosure) > 0
        owasp_assessment['A05_Security_Misconfiguration'] = {
            'vulnerable': has_info_disclosure or result.server_info_disclosed,
            'details': []
        }
        if has_info_disclosure:
            owasp_assessment['A05_Security_Misconfiguration']['details'].append("Information disclosure detected")
        if result.server_info_disclosed:
            owasp_assessment['A05_Security_Misconfiguration']['details'].append("Server information disclosed")
        
        # A06:2021 – Vulnerable and Outdated Components
        # This would require additional component detection
        owasp_assessment['A06_Vulnerable_Components'] = {
            'vulnerable': False,
            'details': ["Component analysis requires deeper inspection"]
        }
        
        # A07:2021 – Identification and Authentication Failures
        owasp_assessment['A07_Auth_Failures'] = {
            'vulnerable': result.weak_authentication or result.session_fixation_vulnerable,
            'details': []
        }
        if result.weak_authentication:
            owasp_assessment['A07_Auth_Failures']['details'].append("Weak authentication mechanisms")
        if result.session_fixation_vulnerable:
            owasp_assessment['A07_Auth_Failures']['details'].append("Session fixation vulnerability")
        
        # A08:2021 – Software and Data Integrity Failures
        owasp_assessment['A08_Integrity_Failures'] = {
            'vulnerable': result.unrestricted_file_upload,
            'details': []
        }
        if result.unrestricted_file_upload:
            owasp_assessment['A08_Integrity_Failures']['details'].append("Unrestricted file upload detected")
        
        # A09:2021 – Security Logging and Monitoring Failures
        owasp_assessment['A09_Logging_Failures'] = {
            'vulnerable': True,  # Cannot easily test without access
            'details': ["Logging assessment requires access to server logs"]
        }
        
        # A10:2021 – Server-Side Request Forgery
        owasp_assessment['A10_SSRF'] = {
            'vulnerable': False,  # Would require specific testing
            'details': ["SSRF testing requires specific test cases"]
        }
        
        result.owasp_issues = owasp_assessment
    
    async def _check_cms_vulnerabilities(self, client: httpx.AsyncClient, base_url: str, asset: Asset, result: WebSecurityResult):
        """Check for CMS and framework specific vulnerabilities"""
        tech_stack = getattr(asset, 'tech_stack', [])
        
        # WordPress specific checks
        if any('wordpress' in tech.lower() for tech in tech_stack):
            wp_paths = ['/wp-admin/', '/wp-content/', '/wp-includes/', '/xmlrpc.php']
            for path in wp_paths:
                try:
                    test_url = f"{base_url.rstrip('/')}{path}"
                    response = await client.get(test_url)
                    if response.status_code == 200:
                        if path == '/xmlrpc.php':
                            result.cms_vulnerabilities.append("WordPress XML-RPC enabled (potential DDoS vector)")
                        elif path == '/wp-admin/':
                            result.cms_vulnerabilities.append("WordPress admin accessible")
                except Exception:
                    pass
        
        # Check for common framework indicators
        framework_indicators = {
            'django': ['/admin/', '/__debug__/'],
            'rails': ['/rails/info/', '/assets/'],
            'laravel': ['/telescope/', '/.env'],
            'spring': ['/actuator/', '/h2-console/']
        }
        
        for framework, paths in framework_indicators.items():
            if any(framework in tech.lower() for tech in tech_stack):
                for path in paths:
                    try:
                        test_url = f"{base_url.rstrip('/')}{path}"
                        response = await client.get(test_url)
                        if response.status_code == 200:
                            result.framework_vulnerabilities.append(f"{framework.capitalize()} debug endpoint accessible: {path}")
                    except Exception:
                        pass
    
    async def _check_waf_protection(self, url: str, result: WebSecurityResult):
        """Check for Web Application Firewall protection using wafw00f"""
        logger.info(f"WAF DETECTION: Starting WAF check for {url}")
        
        if not self.waf_detection_enabled:
            logger.warning(f"WAF DETECTION: WAF detection is disabled for {url}")
            return
        
        try:
            logger.info(f"WAF DETECTION: Checking WAF protection for {url}")
            
            # Extract domain from URL for wafw00f
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            target = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            logger.info(f"WAF DETECTION: Running wafw00f on target: {target}")
            
            # Run wafw00f as subprocess with timeout handling
            cmd = ["wafw00f", "-a", target, "-f", "json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Apply timeout using asyncio.wait_for
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.waf_timeout
            )
            
            logger.info(f"WAF DETECTION: wafw00f completed with return code: {process.returncode}")
            
            if process.returncode == 0:
                logger.info(f"WAF DETECTION: wafw00f output: {stdout.decode()[:200]}...")
                try:
                    waf_result = json.loads(stdout.decode())
                    await self._process_waf_results(waf_result, result, url)
                except json.JSONDecodeError:
                    logger.info(f"WAF DETECTION: JSON decode failed, falling back to text parsing")
                    # Fallback to text parsing if JSON fails
                    await self._process_waf_text_results(stdout.decode(), result, url)
            else:
                # If wafw00f fails, consider it as no WAF detected
                logger.warning(f"WAF DETECTION: wafw00f failed for {url}: {stderr.decode()}")
                await self._handle_no_waf_detected(result, url)
            
        except asyncio.TimeoutError:
            logger.warning(f"WAF DETECTION: WAF detection timed out for {url}")
            await self._handle_no_waf_detected(result, url)
        except Exception as e:
            logger.error(f"WAF DETECTION: WAF detection failed for {url}: {str(e)}")
            await self._handle_no_waf_detected(result, url)
    
    async def _process_waf_results(self, waf_result: dict, result: WebSecurityResult, url: str):
        """Process WAF detection results from wafw00f JSON output"""
        detected_wafs = []
        
        # Parse wafw00f JSON output
        for target_data in waf_result.values():
            if isinstance(target_data, dict):
                detections = target_data.get('detected', [])
                for detection in detections:
                    if isinstance(detection, dict):
                        waf_name = detection.get('name', 'Unknown WAF')
                        manufacturer = detection.get('manufacturer', '')
                        detected_wafs.append(f"{waf_name} ({manufacturer})" if manufacturer else waf_name)
        
        if detected_wafs:
            logger.info(f"WAF detected for {url}: {', '.join(detected_wafs)}")
            result.security_issues.append(f"WAF protection detected: {', '.join(detected_wafs)}")
            # Add positive security note
            if not hasattr(result, 'security_positives'):
                result.security_positives = []
            result.security_positives.append(f"Web Application Firewall protection: {', '.join(detected_wafs)}")
        else:
            await self._handle_no_waf_detected(result, url)
    
    async def _process_waf_text_results(self, output: str, result: WebSecurityResult, url: str):
        """Process WAF detection results from wafw00f text output"""
        detected_wafs = []
        
        # Parse text output for WAF detections
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if 'is behind' in line.lower() or 'protected by' in line.lower():
                # Extract WAF name from the line
                waf_match = re.search(r'behind\s+(.+?)(?:\s+\(|$)', line, re.IGNORECASE)
                if not waf_match:
                    waf_match = re.search(r'protected by\s+(.+?)(?:\s+\(|$)', line, re.IGNORECASE)
                
                if waf_match:
                    waf_name = waf_match.group(1).strip()
                    detected_wafs.append(waf_name)
        
        if detected_wafs:
            logger.info(f"WAF detected for {url}: {', '.join(detected_wafs)}")
            result.security_issues.append(f"WAF protection detected: {', '.join(detected_wafs)}")
            # Add positive security note
            if not hasattr(result, 'security_positives'):
                result.security_positives = []
            result.security_positives.append(f"Web Application Firewall protection: {', '.join(detected_wafs)}")
        else:
            await self._handle_no_waf_detected(result, url)
    
    async def _handle_no_waf_detected(self, result: WebSecurityResult, url: str):
        """Handle case when no WAF is detected"""
        logger.warning(f"WAF DETECTION: No WAF protection detected for {url}")
        result.security_issues.append("No Web Application Firewall (WAF) protection detected")
        
        # Add to missing security features
        if not hasattr(result, 'missing_security_features'):
            result.missing_security_features = []
        result.missing_security_features.append("Web Application Firewall (WAF)")
        
        logger.info(f"WAF DETECTION: Added missing WAF to security features for {url}")
    
    def _calculate_web_security_score(self, result: WebSecurityResult):
        """Calculate web security score (0-100)"""
        score = 100.0
        
        # Security headers (30 points total)
        header_penalty = len(result.missing_headers) * 5
        insecure_header_penalty = len(result.insecure_headers) * 3
        score -= min(30, header_penalty + insecure_header_penalty)
        
        # XSS vulnerabilities (25 points)
        if result.xss_vulnerable:
            score -= 25
        
        # SQL injection vulnerabilities (30 points)
        if result.sqli_vulnerable:
            score -= 30
        
        # Directory traversal (20 points)
        if result.directory_traversal_vulnerable:
            score -= 20
        
        # Information disclosure (15 points)
        info_disclosure_penalty = min(15, len(result.information_disclosure) * 2)
        score -= info_disclosure_penalty
        
        # Authentication issues (20 points)
        if result.weak_authentication:
            score -= 15
        if result.insecure_session_management:
            score -= 10
        
        # File upload issues (15 points)
        if result.unrestricted_file_upload:
            score -= 15
        
        # CSP bonus/penalty
        if result.csp_enabled:
            score += 5
            if result.csp_unsafe_inline or result.csp_unsafe_eval:
                score -= 5
        else:
            score -= 10
        
        # WAF protection (10 points penalty for missing WAF)
        if hasattr(result, 'missing_security_features') and 'Web Application Firewall (WAF)' in result.missing_security_features:
            score -= 10
        elif hasattr(result, 'security_positives') and any('Web Application Firewall' in positive for positive in result.security_positives):
            score += 5  # Bonus for having WAF
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.web_security_score = score
        
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
    
    def _generate_web_security_recommendations(self, result: WebSecurityResult):
        """Generate web security recommendations"""
        recommendations = []
        
        # Security headers recommendations
        for header in result.missing_headers:
            header_info = self.security_headers.get(header, {})
            desc = header_info.get('description', 'Security enhancement')
            recommendations.append(f"Implement {header} header - {desc}")
        
        # XSS recommendations
        if result.xss_vulnerable:
            recommendations.append("Implement input validation and output encoding to prevent XSS attacks")
            recommendations.append("Use Content Security Policy (CSP) to mitigate XSS risks")
            recommendations.append("Sanitize all user inputs before processing or displaying")
        
        # SQL injection recommendations
        if result.sqli_vulnerable:
            recommendations.append("Use parameterized queries/prepared statements to prevent SQL injection")
            recommendations.append("Implement input validation for all database queries")
            recommendations.append("Apply principle of least privilege for database connections")
        
        # Directory traversal recommendations
        if result.directory_traversal_vulnerable:
            recommendations.append("Validate and sanitize all file path inputs")
            recommendations.append("Use allowlists for file access patterns")
            recommendations.append("Implement proper access controls for file operations")
        
        # Information disclosure recommendations
        if result.information_disclosure:
            recommendations.append("Remove or secure sensitive files and directories")
            recommendations.append("Disable directory listings")
            recommendations.append("Remove server information headers")
        
        # Authentication recommendations
        if result.weak_authentication:
            recommendations.append("Implement strong authentication mechanisms")
            recommendations.append("Use multi-factor authentication where possible")
            recommendations.append("Enforce strong password policies")
        
        if result.insecure_session_management:
            recommendations.append("Implement CSRF protection for all forms")
            recommendations.append("Use secure session management practices")
            recommendations.append("Implement proper session timeout mechanisms")
        
        # File upload recommendations
        if result.unrestricted_file_upload:
            recommendations.append("Implement file type validation for uploads")
            recommendations.append("Scan uploaded files for malware")
            recommendations.append("Store uploaded files outside web root")
        
        # CSP recommendations
        if not result.csp_enabled:
            recommendations.append("Implement Content Security Policy (CSP)")
        elif result.csp_unsafe_inline or result.csp_unsafe_eval:
            recommendations.append("Remove 'unsafe-inline' and 'unsafe-eval' from CSP")
        
        # WAF recommendations
        if hasattr(result, 'missing_security_features') and 'Web Application Firewall (WAF)' in result.missing_security_features:
            recommendations.append("Implement a Web Application Firewall (WAF) to protect against common web attacks")
            recommendations.append("Consider cloud-based WAF solutions like Cloudflare, AWS WAF, or Azure Application Gateway")
        elif hasattr(result, 'security_positives') and any('Web Application Firewall' in positive for positive in result.security_positives):
            recommendations.append("Ensure WAF rules are regularly updated and properly configured")
            recommendations.append("Monitor WAF logs for attack patterns and adjust rules accordingly")
        
        # General recommendations
        if result.web_security_score < 70:
            recommendations.append("Conduct regular security assessments and penetration testing")
            if not (hasattr(result, 'security_positives') and any('Web Application Firewall' in positive for positive in result.security_positives)):
                recommendations.append("Implement Web Application Firewall (WAF)")
            recommendations.append("Follow OWASP secure coding practices")
        
        result.recommendations = recommendations 