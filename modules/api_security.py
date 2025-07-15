"""
API Security Testing Module
Performs comprehensive API security testing including endpoint discovery,
authentication bypass, authorization testing, input validation, and API security assessment.
"""
import asyncio
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
import httpx
from urllib.parse import urljoin, urlparse
import base64

from models import APISecurityResult, Asset
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class APISecurityAnalyzer:
    """API security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        
        # Common API endpoints to discover
        self.api_discovery_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest',
            '/graphql',
            '/soap',
            '/swagger',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api-docs',
            '/docs',
            '/documentation',
            '/api/docs',
            '/api/swagger',
            '/api/openapi',
            '/v1',
            '/v2',
            '/v3'
        ]
        
        # GraphQL discovery paths
        self.graphql_paths = [
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/api/query'
        ]
        
        # SOAP discovery paths
        self.soap_paths = [
            '/soap',
            '/wsdl',
            '/api/soap',
            '/services',
            '/webservice',
            '/ws'
        ]
        
        # Common API authentication headers
        self.auth_headers = [
            'authorization',
            'x-api-key',
            'x-auth-token',
            'x-access-token',
            'x-session-token',
            'api-key',
            'auth-token',
            'access-token',
            'session-token'
        ]
        
        # Authentication bypass techniques
        self.auth_bypass_tests = [
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Real-IP', 'value': '127.0.0.1'},
            {'header': 'X-Originating-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-Addr', 'value': '127.0.0.1'},
            {'header': 'X-Forwarded-Host', 'value': 'localhost'},
            {'header': 'X-Rewrite-URL', 'value': '/admin'},
            {'header': 'X-Original-URL', 'value': '/admin'},
            {'header': 'User-Agent', 'value': 'GoogleBot'},
            {'header': 'Referer', 'value': 'https://google.com'}
        ]
        
        # Common injection payloads for API testing
        self.injection_payloads = [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "${jndi:ldap://test.com}",
            "../../../etc/passwd",
            "'; DROP TABLE users--",
            "1 UNION SELECT NULL--"
        ]
        
        # Rate limiting test patterns
        self.rate_limit_tests = {
            'burst': 50,  # Number of requests in burst
            'sustained': 10,  # Requests per second for sustained test
            'duration': 5  # Duration in seconds
        }
    
    async def analyze_api_security(self, assets: List[Asset]) -> List[APISecurityResult]:
        """Perform comprehensive API security analysis"""
        logger.info(f"Starting API security analysis for {len(assets)} assets")
        
        results = []
        
        # Group assets by domain for analysis
        domains = list(set(asset.domain for asset in assets))
        
        # Analyze each domain with limited concurrency
        semaphore = asyncio.Semaphore(2)  # Limit concurrent API tests
        
        async def limited_analysis(domain):
            async with semaphore:
                domain_assets = [asset for asset in assets if asset.domain == domain]
                return await self._analyze_domain_api_security(domain, domain_assets)
        
        api_results = await asyncio.gather(*[limited_analysis(domain) for domain in domains], 
                                         return_exceptions=True)
        
        # Filter out exceptions and None results
        for i, result in enumerate(api_results):
            if isinstance(result, Exception):
                logger.error(f"API analysis failed for {domains[i]}: {result}")
            elif result:
                results.append(result)
        
        logger.info(f"Completed API security analysis: {len(results)} results")
        return results
    
    async def _analyze_domain_api_security(self, domain: str, assets: List[Asset]) -> Optional[APISecurityResult]:
        """Analyze API security for a single domain"""
        try:
            # SECURITY: Validate domain before analysis
            if not is_safe_domain(domain):
                logger.warning(f"Skipping API analysis for potentially unsafe domain: {domain}")
                return None
            
            logger.info(f"Analyzing API security for {domain}")
            
            # Create result object
            result = APISecurityResult(domain=domain)
            
            # Discover API endpoints
            await self._discover_api_endpoints(domain, assets, result)
            
            # Test authentication and authorization
            await self._test_authentication_security(domain, result)
            
            # Test input validation
            await self._test_input_validation(domain, result)
            
            # Test rate limiting
            await self._test_rate_limiting(domain, result)
            
            # Check for information disclosure
            await self._check_api_information_disclosure(domain, result)
            
            # Calculate API security score
            self._calculate_api_security_score(result)
            
            # Generate recommendations
            self._generate_api_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"API security analysis failed for {domain}: {str(e)}")
            return None
    
    async def _discover_api_endpoints(self, domain: str, assets: List[Asset], result: APISecurityResult):
        """Discover API endpoints"""
        try:
            logger.debug(f"Discovering API endpoints for {domain}")
            
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                for asset in assets:
                    base_url = f"{asset.protocol}://{asset.domain}:{asset.port}"
                    
                    # Test common API paths
                    for api_path in self.api_discovery_paths:
                        try:
                            test_url = urljoin(base_url, api_path)
                            
                            # SECURITY: Validate URL before making request
                            try:
                                sanitized_url = validate_external_url(test_url)
                                test_url = sanitized_url
                            except ValueError:
                                continue
                            
                            response = await client.get(test_url)
                            
                            if response.status_code in [200, 401, 403]:
                                # Found potential API endpoint
                                if test_url not in result.api_endpoints:
                                    result.api_endpoints.append(test_url)
                                
                                # Classify endpoint type
                                await self._classify_endpoint(test_url, response, result)
                                
                        except Exception as e:
                            logger.debug(f"API discovery failed for {test_url}: {str(e)}")
                    
                    # Check for API documentation exposure
                    await self._check_api_documentation(base_url, result, client)
            
        except Exception as e:
            logger.debug(f"API endpoint discovery failed for {domain}: {str(e)}")
    
    async def _classify_endpoint(self, url: str, response: httpx.Response, result: APISecurityResult):
        """Classify discovered endpoints by type"""
        try:
            content_type = response.headers.get('content-type', '').lower()
            response_text = response.text.lower()
            
            # GraphQL detection
            if ('graphql' in url.lower() or 
                'query' in response_text or 
                '__schema' in response_text or
                'application/graphql' in content_type):
                if url not in result.graphql_endpoints:
                    result.graphql_endpoints.append(url)
            
            # SOAP detection
            elif ('soap' in url.lower() or 
                  'wsdl' in url.lower() or
                  'soap:envelope' in response_text or
                  'text/xml' in content_type):
                if url not in result.soap_endpoints:
                    result.soap_endpoints.append(url)
            
            # REST detection (default for other APIs)
            elif ('application/json' in content_type or
                  'api' in url.lower() or
                  response.status_code == 200):
                if url not in result.rest_endpoints:
                    result.rest_endpoints.append(url)
            
        except Exception as e:
            logger.debug(f"Endpoint classification failed for {url}: {str(e)}")
    
    async def _check_api_documentation(self, base_url: str, result: APISecurityResult, client: httpx.AsyncClient):
        """Check for exposed API documentation"""
        try:
            doc_paths = [
                '/swagger.json',
                '/swagger.yaml',
                '/openapi.json',
                '/api-docs',
                '/docs',
                '/swagger-ui',
                '/redoc'
            ]
            
            for doc_path in doc_paths:
                try:
                    doc_url = urljoin(base_url, doc_path)
                    
                    # SECURITY: Validate URL before making request
                    try:
                        sanitized_url = validate_external_url(doc_url)
                        doc_url = sanitized_url
                    except ValueError:
                        continue
                    
                    response = await client.get(doc_url)
                    
                    if response.status_code == 200:
                        result.api_documentation_exposed = True
                        result.security_issues.append(f"API documentation exposed: {doc_path}")
                        
                        # Check for sensitive information in documentation
                        if any(keyword in response.text.lower() for keyword in 
                               ['password', 'secret', 'key', 'token', 'credential']):
                            result.sensitive_data_exposed.append(f"Sensitive data in API docs: {doc_path}")
                
                except Exception as e:
                    logger.debug(f"API documentation check failed for {doc_path}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"API documentation check failed: {str(e)}")
    
    async def _test_authentication_security(self, domain: str, result: APISecurityResult):
        """Test API authentication and authorization security"""
        try:
            logger.debug(f"Testing authentication security for {domain}")
            
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                for endpoint in result.api_endpoints[:5]:  # Limit to first 5 endpoints
                    
                    # Test authentication bypass techniques
                    for bypass_test in self.auth_bypass_tests:
                        try:
                            headers = {bypass_test['header']: bypass_test['value']}
                            
                            # Test without authentication
                            response_no_auth = await client.get(endpoint)
                            
                            # Test with bypass headers
                            response_bypass = await client.get(endpoint, headers=headers)
                            
                            # Check if bypass was successful
                            if (response_no_auth.status_code in [401, 403] and 
                                response_bypass.status_code == 200):
                                result.authentication_bypass.append(f"{endpoint}: {bypass_test['header']}")
                                result.security_issues.append(f"Authentication bypass via {bypass_test['header']}")
                            
                        except Exception as e:
                            logger.debug(f"Auth bypass test failed for {endpoint}: {str(e)}")
                    
                    # Test for weak authentication
                    await self._test_weak_authentication(endpoint, result, client)
                    
                    # Test authorization issues
                    await self._test_authorization_issues(endpoint, result, client)
            
        except Exception as e:
            logger.debug(f"Authentication security test failed for {domain}: {str(e)}")
    
    async def _test_weak_authentication(self, endpoint: str, result: APISecurityResult, client: httpx.AsyncClient):
        """Test for weak authentication mechanisms"""
        try:
            # Test common weak credentials
            weak_credentials = [
                {'user': 'admin', 'pass': 'admin'},
                {'user': 'admin', 'pass': 'password'},
                {'user': 'admin', 'pass': '123456'},
                {'user': 'test', 'pass': 'test'},
                {'user': 'guest', 'pass': 'guest'}
            ]
            
            for cred in weak_credentials:
                try:
                    # Test Basic Auth
                    auth_string = base64.b64encode(f"{cred['user']}:{cred['pass']}".encode()).decode()
                    headers = {'Authorization': f'Basic {auth_string}'}
                    
                    response = await client.get(endpoint, headers=headers)
                    
                    if response.status_code == 200:
                        result.weak_authentication.append(f"{endpoint}: {cred['user']}:{cred['pass']}")
                        result.security_issues.append(f"Weak credentials accepted: {cred['user']}:{cred['pass']}")
                
                except Exception as e:
                    logger.debug(f"Weak auth test failed for {endpoint}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"Weak authentication test failed: {str(e)}")
    
    async def _test_authorization_issues(self, endpoint: str, result: APISecurityResult, client: httpx.AsyncClient):
        """Test for authorization issues like privilege escalation"""
        try:
            # Test different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
            
            for method in methods:
                try:
                    if method == 'GET':
                        response = await client.get(endpoint)
                    elif method == 'POST':
                        response = await client.post(endpoint, json={})
                    elif method == 'PUT':
                        response = await client.put(endpoint, json={})
                    elif method == 'DELETE':
                        response = await client.delete(endpoint)
                    elif method == 'PATCH':
                        response = await client.patch(endpoint, json={})
                    elif method == 'OPTIONS':
                        response = await client.options(endpoint)
                    else:
                        continue
                    
                    # Check for unexpected access
                    if response.status_code == 200 and method in ['PUT', 'DELETE', 'PATCH']:
                        result.authorization_issues.append(f"{endpoint}: Unprotected {method} method")
                        result.security_issues.append(f"Unprotected {method} method on {endpoint}")
                
                except Exception as e:
                    logger.debug(f"Authorization test failed for {endpoint} {method}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"Authorization test failed: {str(e)}")
    
    async def _test_input_validation(self, domain: str, result: APISecurityResult):
        """Test API input validation"""
        try:
            logger.debug(f"Testing input validation for {domain}")
            
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                for endpoint in result.api_endpoints[:3]:  # Limit to first 3 endpoints
                    
                    # Test injection vulnerabilities
                    for payload in self.injection_payloads:
                        try:
                            # Test GET parameters
                            test_url = f"{endpoint}?test={payload}"
                            response = await client.get(test_url)
                            
                            # Check for SQL error messages
                            if self._check_sql_injection_response(response):
                                result.injection_vulnerabilities.append(f"SQL injection in {endpoint}")
                                result.security_issues.append(f"SQL injection vulnerability: {endpoint}")
                            
                            # Test POST data
                            try:
                                response = await client.post(endpoint, json={'test': payload})
                                if self._check_sql_injection_response(response):
                                    result.injection_vulnerabilities.append(f"SQL injection in {endpoint} (POST)")
                            except:
                                pass
                                
                        except Exception as e:
                            logger.debug(f"Input validation test failed for {endpoint}: {str(e)}")
                    
                    # Test for input validation issues
                    await self._test_input_validation_issues(endpoint, result, client)
            
        except Exception as e:
            logger.debug(f"Input validation test failed for {domain}: {str(e)}")
    
    def _check_sql_injection_response(self, response: httpx.Response) -> bool:
        """Check response for SQL injection indicators"""
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-',
            'postgresql',
            'sqlexception',
            'sqlite_',
            'sqlstate',
            'database error'
        ]
        
        response_text = response.text.lower()
        return any(error in response_text for error in sql_errors)
    
    async def _test_input_validation_issues(self, endpoint: str, result: APISecurityResult, client: httpx.AsyncClient):
        """Test for general input validation issues"""
        try:
            # Test oversized input
            large_payload = 'A' * 10000
            
            try:
                response = await client.post(endpoint, json={'test': large_payload})
                if response.status_code == 500:
                    result.input_validation_issues.append(f"Large input causes server error: {endpoint}")
            except:
                pass
            
            # Test special characters
            special_chars = ['<', '>', '"', "'", '&', '%', '\x00', '\n', '\r']
            
            for char in special_chars:
                try:
                    response = await client.post(endpoint, json={'test': char})
                    if 'error' in response.text.lower() or response.status_code == 500:
                        result.input_validation_issues.append(f"Special character handling issue: {endpoint}")
                        break
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Input validation issues test failed: {str(e)}")
    
    async def _test_rate_limiting(self, domain: str, result: APISecurityResult):
        """Test API rate limiting"""
        try:
            logger.debug(f"Testing rate limiting for {domain}")
            
            if not result.api_endpoints:
                return
            
            # Test first endpoint only to avoid being too aggressive
            test_endpoint = result.api_endpoints[0]
            
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                # Burst test
                success_count = 0
                
                for i in range(self.rate_limit_tests['burst']):
                    try:
                        response = await client.get(test_endpoint)
                        if response.status_code not in [429, 503]:  # Not rate limited
                            success_count += 1
                        else:
                            break  # Hit rate limit
                    except:
                        break
                
                # If we succeeded with most requests, rate limiting might not be implemented
                if success_count > self.rate_limit_tests['burst'] * 0.8:
                    result.rate_limiting_enabled = False
                    result.security_issues.append("Rate limiting not implemented")
                else:
                    result.rate_limiting_enabled = True
                
                # Test rate limit bypass
                if not result.rate_limiting_enabled:
                    bypass_headers = [
                        {'X-Forwarded-For': '1.2.3.4'},
                        {'X-Real-IP': '1.2.3.4'},
                        {'User-Agent': 'Different-Agent'}
                    ]
                    
                    for headers in bypass_headers:
                        try:
                            response = await client.get(test_endpoint, headers=headers)
                            if response.status_code == 200:
                                result.rate_limit_bypass = True
                                result.security_issues.append("Rate limit bypass possible")
                                break
                        except:
                            pass
            
        except Exception as e:
            logger.debug(f"Rate limiting test failed for {domain}: {str(e)}")
    
    async def _check_api_information_disclosure(self, domain: str, result: APISecurityResult):
        """Check for API information disclosure"""
        try:
            logger.debug(f"Checking API information disclosure for {domain}")
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for endpoint in result.api_endpoints[:3]:  # Limit to first 3 endpoints
                    try:
                        # Test for verbose error messages
                        response = await client.get(f"{endpoint}/nonexistent")
                        
                        if response.status_code in [404, 500]:
                            # Check for stack traces or internal paths
                            if any(keyword in response.text.lower() for keyword in 
                                   ['traceback', 'stack trace', 'internal server error', 
                                    'debug', 'exception', '/home/', '/var/', 'c:\\']):
                                result.sensitive_data_exposed.append(f"Verbose error messages: {endpoint}")
                                result.security_issues.append(f"Information disclosure in error messages: {endpoint}")
                        
                        # Check for API versioning issues
                        if '/v' in endpoint:
                            # Try different versions
                            for version in ['v1', 'v2', 'v3', 'v0']:
                                try:
                                    version_endpoint = re.sub(r'/v\d+', f'/{version}', endpoint)
                                    version_response = await client.get(version_endpoint)
                                    
                                    if version_response.status_code == 200:
                                        if version_endpoint not in result.api_versions:
                                            result.api_versions.append(version_endpoint)
                                        
                                        # Check if it's a deprecated version
                                        if 'deprecated' in version_response.text.lower():
                                            result.deprecated_versions.append(version_endpoint)
                                            result.security_issues.append(f"Deprecated API version accessible: {version_endpoint}")
                                
                                except:
                                    pass
                    
                    except Exception as e:
                        logger.debug(f"Information disclosure check failed for {endpoint}: {str(e)}")
            
        except Exception as e:
            logger.debug(f"API information disclosure check failed for {domain}: {str(e)}")
    
    def _calculate_api_security_score(self, result: APISecurityResult):
        """Calculate API security score (0-100)"""
        score = 100.0
        
        # Authentication issues (30 points)
        auth_penalty = min(30, len(result.authentication_bypass) * 15 + len(result.weak_authentication) * 10)
        score -= auth_penalty
        
        # Authorization issues (25 points)
        authz_penalty = min(25, len(result.authorization_issues) * 10)
        score -= authz_penalty
        
        # Input validation issues (20 points)
        input_penalty = min(20, len(result.input_validation_issues) * 5 + len(result.injection_vulnerabilities) * 10)
        score -= input_penalty
        
        # Rate limiting (15 points)
        if not result.rate_limiting_enabled:
            score -= 10
        if result.rate_limit_bypass:
            score -= 5
        
        # Information disclosure (10 points)
        info_penalty = min(10, len(result.sensitive_data_exposed) * 5)
        score -= info_penalty
        
        # API documentation exposure (5 points)
        if result.api_documentation_exposed:
            score -= 5
        
        # Deprecated versions (5 points)
        if result.deprecated_versions:
            score -= 5
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.api_security_score = score
    
    def _generate_api_recommendations(self, result: APISecurityResult):
        """Generate API security recommendations"""
        recommendations = []
        
        # Authentication recommendations
        if result.authentication_bypass:
            recommendations.append("Fix authentication bypass vulnerabilities")
            recommendations.append("Implement proper authentication checks on all endpoints")
        
        if result.weak_authentication:
            recommendations.append("Enforce strong authentication mechanisms")
            recommendations.append("Remove or secure endpoints with weak credentials")
        
        # Authorization recommendations
        if result.authorization_issues:
            recommendations.append("Implement proper authorization controls")
            recommendations.append("Restrict HTTP methods based on user permissions")
            recommendations.append("Apply principle of least privilege")
        
        # Input validation recommendations
        if result.input_validation_issues or result.injection_vulnerabilities:
            recommendations.append("Implement comprehensive input validation")
            recommendations.append("Use parameterized queries to prevent SQL injection")
            recommendations.append("Sanitize and validate all user inputs")
        
        # Rate limiting recommendations
        if not result.rate_limiting_enabled:
            recommendations.append("Implement rate limiting to prevent abuse")
            recommendations.append("Use progressive delays for repeated failed attempts")
        
        if result.rate_limit_bypass:
            recommendations.append("Secure rate limiting implementation against bypass techniques")
        
        # Information disclosure recommendations
        if result.sensitive_data_exposed:
            recommendations.append("Remove sensitive information from API responses")
            recommendations.append("Implement generic error messages")
            recommendations.append("Disable debug mode in production")
        
        if result.api_documentation_exposed:
            recommendations.append("Secure or remove publicly accessible API documentation")
            recommendations.append("Remove sensitive information from API documentation")
        
        # Version management recommendations
        if result.deprecated_versions:
            recommendations.append("Disable or secure deprecated API versions")
            recommendations.append("Implement proper API version lifecycle management")
        
        # General recommendations
        if result.api_security_score < 70:
            recommendations.append("Implement comprehensive API security testing")
            recommendations.append("Use API gateways for centralized security controls")
            recommendations.append("Regular security assessments and penetration testing")
        
        result.recommendations = recommendations 