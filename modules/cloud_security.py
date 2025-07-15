"""
Cloud Security Assessment Module
Performs cloud security analysis including cloud provider detection,
public resource identification, misconfiguration detection, and CDN analysis.
"""
import asyncio
import re
import logging
import json
from typing import List, Dict, Any, Optional, Tuple
import httpx
import dns.resolver

from models import CloudSecurityResult, Asset
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class CloudSecurityAnalyzer:
    """Cloud security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        
        # Cloud provider indicators
        self.cloud_indicators = {
            'aws': {
                'domains': [
                    'amazonaws.com',
                    'aws.amazon.com',
                    'elasticbeanstalk.com',
                    'cloudfront.net',
                    's3.amazonaws.com',
                    's3-website',
                    'awsdns'
                ],
                'headers': [
                    'x-amz-',
                    'x-amzn-',
                    'server: AmazonS3',
                    'server: CloudFront'
                ],
                'services': {
                    'CloudFront': ['cloudfront.net'],
                    'S3': ['s3.amazonaws.com', 's3-website'],
                    'ELB': ['elb.amazonaws.com'],
                    'EC2': ['compute.amazonaws.com'],
                    'Route53': ['awsdns']
                }
            },
            'azure': {
                'domains': [
                    'azure.com',
                    'azurewebsites.net',
                    'blob.core.windows.net',
                    'cloudapp.net',
                    'azurefd.net',
                    'trafficmanager.net'
                ],
                'headers': [
                    'x-azure-',
                    'server: Microsoft-Azure',
                    'x-ms-'
                ],
                'services': {
                    'App Service': ['azurewebsites.net'],
                    'Blob Storage': ['blob.core.windows.net'],
                    'CDN': ['azurefd.net'],
                    'Traffic Manager': ['trafficmanager.net']
                }
            },
            'gcp': {
                'domains': [
                    'googleusercontent.com',
                    'googleapis.com',
                    'appspot.com',
                    'cloudfunctions.net',
                    'run.app',
                    'firebaseapp.com'
                ],
                'headers': [
                    'x-goog-',
                    'server: Google',
                    'x-cloud-trace-context'
                ],
                'services': {
                    'App Engine': ['appspot.com'],
                    'Cloud Run': ['run.app'],
                    'Cloud Functions': ['cloudfunctions.net'],
                    'Firebase': ['firebaseapp.com'],
                    'Cloud Storage': ['googleapis.com']
                }
            },
            'cloudflare': {
                'domains': [
                    'cloudflare.com',
                    'cloudflaressl.com'
                ],
                'headers': [
                    'cf-ray',
                    'server: cloudflare',
                    'cf-cache-status'
                ],
                'services': {
                    'CDN': ['cloudflare.com'],
                    'DNS': ['cloudflare.com']
                }
            }
        }
        
        # Common S3 bucket naming patterns
        self.s3_bucket_patterns = [
            r'https?://([a-z0-9.-]+)\.s3\.amazonaws\.com',
            r'https?://s3\.amazonaws\.com/([a-z0-9.-]+)',
            r'https?://([a-z0-9.-]+)\.s3-[a-z0-9-]+\.amazonaws\.com',
            r'https?://s3-[a-z0-9-]+\.amazonaws\.com/([a-z0-9.-]+)'
        ]
        
        # Azure storage patterns
        self.azure_storage_patterns = [
            r'https?://([a-z0-9]+)\.blob\.core\.windows\.net',
            r'https?://([a-z0-9]+)\.file\.core\.windows\.net',
            r'https?://([a-z0-9]+)\.table\.core\.windows\.net'
        ]
        
        # GCP storage patterns
        self.gcp_storage_patterns = [
            r'https?://storage\.googleapis\.com/([a-z0-9.-]+)',
            r'https?://([a-z0-9.-]+)\.storage\.googleapis\.com'
        ]
        
        # CDN providers
        self.cdn_providers = {
            'cloudflare': ['cloudflare.com', 'cf-ray'],
            'cloudfront': ['cloudfront.net', 'x-amz-cf-id'],
            'fastly': ['fastly.com', 'fastly-debug-digest'],
            'akamai': ['akamai.com', 'akamai-ghost'],
            'maxcdn': ['maxcdn.com', 'x-cache'],
            'azure_cdn': ['azurefd.net', 'x-azure-ref'],
            'google_cdn': ['googleapis.com', 'x-goog-'],
            'keycdn': ['keycdn.com', 'x-edge-location']
        }
        
        # Common cloud misconfigurations to check
        self.misconfiguration_checks = [
            'public_read_access',
            'public_write_access',
            'default_credentials',
            'insecure_permissions',
            'missing_encryption',
            'exposed_metadata'
        ]
    
    async def analyze_cloud_security(self, assets: List[Asset]) -> List[CloudSecurityResult]:
        """Perform comprehensive cloud security analysis"""
        logger.info(f"Starting cloud security analysis for {len(assets)} assets")
        
        results = []
        
        # Group assets by domain for analysis
        domains = list(set(asset.domain for asset in assets))
        
        # Analyze each domain with limited concurrency
        semaphore = asyncio.Semaphore(3)  # Limit concurrent cloud tests
        
        async def limited_analysis(domain):
            async with semaphore:
                domain_assets = [asset for asset in assets if asset.domain == domain]
                return await self._analyze_domain_cloud_security(domain, domain_assets)
        
        cloud_results = await asyncio.gather(*[limited_analysis(domain) for domain in domains], 
                                           return_exceptions=True)
        
        # Filter out exceptions and None results
        for i, result in enumerate(cloud_results):
            if isinstance(result, Exception):
                logger.error(f"Cloud analysis failed for {domains[i]}: {result}")
            elif result:
                results.append(result)
        
        logger.info(f"Completed cloud security analysis: {len(results)} results")
        return results
    
    async def _analyze_domain_cloud_security(self, domain: str, assets: List[Asset]) -> Optional[CloudSecurityResult]:
        """Analyze cloud security for a single domain"""
        try:
            # SECURITY: Validate domain before analysis
            if not is_safe_domain(domain):
                logger.warning(f"Skipping cloud analysis for potentially unsafe domain: {domain}")
                return None
            
            logger.info(f"Analyzing cloud security for {domain}")
            
            # Create result object
            result = CloudSecurityResult(domain=domain)
            
            # Detect cloud providers
            await self._detect_cloud_providers(domain, assets, result)
            
            # Check for public cloud resources
            await self._check_public_resources(domain, assets, result)
            
            # Analyze CDN configuration
            await self._analyze_cdn_configuration(domain, assets, result)
            
            # Check for cloud misconfigurations
            await self._check_cloud_misconfigurations(domain, assets, result)
            
            # Check for exposed metadata
            await self._check_metadata_exposure(domain, assets, result)
            
            # Calculate cloud security score
            self._calculate_cloud_security_score(result)
            
            # Generate recommendations
            self._generate_cloud_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Cloud security analysis failed for {domain}: {str(e)}")
            return None
    
    async def _detect_cloud_providers(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Detect cloud providers used by the domain"""
        try:
            logger.debug(f"Detecting cloud providers for {domain}")
            
            # Check domain names and DNS records
            await self._check_dns_for_cloud_providers(domain, result)
            
            # Check HTTP headers and responses
            for asset in assets:
                await self._check_asset_for_cloud_providers(asset, result)
            
            # Determine primary cloud provider
            if result.cloud_services:
                # Count services per provider
                provider_counts = {}
                for service in result.cloud_services:
                    for provider, info in self.cloud_indicators.items():
                        for service_name, indicators in info['services'].items():
                            if any(indicator in service for indicator in indicators):
                                provider_counts[provider] = provider_counts.get(provider, 0) + 1
                
                if provider_counts:
                    result.cloud_provider = max(provider_counts, key=provider_counts.get)
            
        except Exception as e:
            logger.debug(f"Cloud provider detection failed for {domain}: {str(e)}")
    
    async def _check_dns_for_cloud_providers(self, domain: str, result: CloudSecurityResult):
        """Check DNS records for cloud provider indicators"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            # Check CNAME records for cloud services
            try:
                cname_records = resolver.resolve(domain, 'CNAME')
                for cname in cname_records:
                    cname_target = str(cname).rstrip('.')
                    
                    for provider, info in self.cloud_indicators.items():
                        for indicator in info['domains']:
                            if indicator in cname_target:
                                if provider not in result.cloud_services:
                                    result.cloud_services.append(provider)
                                
                                # Identify specific service
                                for service_name, service_indicators in info['services'].items():
                                    if any(si in cname_target for si in service_indicators):
                                        service_info = f"{provider.upper()} {service_name}"
                                        if service_info not in result.cloud_services:
                                            result.cloud_services.append(service_info)
            except:
                pass
            
            # Check A records for cloud IPs (basic check)
            try:
                a_records = resolver.resolve(domain, 'A')
                for a_record in a_records:
                    ip = str(a_record)
                    # AWS IP ranges (simplified check)
                    if ip.startswith(('52.', '54.', '34.', '35.')):
                        if 'aws' not in result.cloud_services:
                            result.cloud_services.append('aws')
            except:
                pass
                
        except Exception as e:
            logger.debug(f"DNS cloud provider check failed for {domain}: {str(e)}")
    
    async def _check_asset_for_cloud_providers(self, asset: Asset, result: CloudSecurityResult):
        """Check individual asset for cloud provider indicators"""
        try:
            # Check headers for cloud indicators
            headers = asset.headers
            
            for provider, info in self.cloud_indicators.items():
                for header_indicator in info['headers']:
                    for header_name, header_value in headers.items():
                        if header_indicator.lower() in f"{header_name.lower()}: {header_value.lower()}":
                            if provider not in result.cloud_services:
                                result.cloud_services.append(provider)
            
            # Check URL and domain for cloud services
            url = f"{asset.protocol}://{asset.domain}:{asset.port}/"
            
            for provider, info in self.cloud_indicators.items():
                for domain_indicator in info['domains']:
                    if domain_indicator in asset.domain:
                        if provider not in result.cloud_services:
                            result.cloud_services.append(provider)
                        
                        # Identify specific service
                        for service_name, service_indicators in info['services'].items():
                            if any(si in asset.domain for si in service_indicators):
                                service_info = f"{provider.upper()} {service_name}"
                                if service_info not in result.cloud_services:
                                    result.cloud_services.append(service_info)
            
        except Exception as e:
            logger.debug(f"Asset cloud provider check failed: {str(e)}")
    
    async def _check_public_resources(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for publicly accessible cloud resources"""
        try:
            logger.debug(f"Checking public cloud resources for {domain}")
            
            # Check for S3 buckets
            await self._check_s3_buckets(domain, assets, result)
            
            # Check for Azure storage
            await self._check_azure_storage(domain, assets, result)
            
            # Check for GCP storage
            await self._check_gcp_storage(domain, assets, result)
            
        except Exception as e:
            logger.debug(f"Public resource check failed for {domain}: {str(e)}")
    
    async def _check_s3_buckets(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for public S3 buckets"""
        try:
            # Common bucket naming patterns
            bucket_names = [
                domain,
                domain.replace('.', '-'),
                domain.replace('.', ''),
                f"{domain}-backup",
                f"{domain}-logs",
                f"{domain}-assets",
                f"{domain}-static",
                f"www-{domain}",
                f"backup-{domain}",
                f"logs-{domain}"
            ]
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for bucket_name in bucket_names:
                    # Test different S3 URL formats
                    s3_urls = [
                        f"https://{bucket_name}.s3.amazonaws.com",
                        f"https://s3.amazonaws.com/{bucket_name}",
                        f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com"
                    ]
                    
                    for s3_url in s3_urls:
                        try:
                            # SECURITY: Validate URL before making request
                            try:
                                sanitized_url = validate_external_url(s3_url)
                                s3_url = sanitized_url
                            except ValueError:
                                continue
                            
                            response = await client.get(s3_url)
                            
                            if response.status_code == 200:
                                # Bucket is publicly accessible
                                result.s3_buckets_found.append(bucket_name)
                                
                                # Check if it's publicly readable
                                if 'ListBucketResult' in response.text or '<Contents>' in response.text:
                                    result.s3_buckets_public.append(bucket_name)
                                    result.public_cloud_resources.append(f"S3 bucket: {bucket_name}")
                                    result.security_issues.append(f"Public S3 bucket found: {bucket_name}")
                                
                        except Exception as e:
                            logger.debug(f"S3 bucket test failed for {bucket_name}: {str(e)}")
                            
        except Exception as e:
            logger.debug(f"S3 bucket check failed for {domain}: {str(e)}")
    
    async def _check_azure_storage(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for public Azure storage"""
        try:
            # Common storage account naming patterns
            storage_names = [
                domain.replace('.', '').replace('-', '')[:24],  # Azure storage names are max 24 chars
                f"{domain.replace('.', '').replace('-', '')[:20]}logs",
                f"{domain.replace('.', '').replace('-', '')[:18]}backup"
            ]
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for storage_name in storage_names:
                    if len(storage_name) < 3 or len(storage_name) > 24:
                        continue
                    
                    try:
                        azure_url = f"https://{storage_name}.blob.core.windows.net"
                        
                        # SECURITY: Validate URL before making request
                        try:
                            sanitized_url = validate_external_url(azure_url)
                            azure_url = sanitized_url
                        except ValueError:
                            continue
                        
                        response = await client.get(azure_url)
                        
                        if response.status_code == 200:
                            # Storage account exists and is accessible
                            result.azure_storage_public.append(storage_name)
                            result.public_cloud_resources.append(f"Azure Storage: {storage_name}")
                            result.security_issues.append(f"Public Azure storage found: {storage_name}")
                            
                    except Exception as e:
                        logger.debug(f"Azure storage test failed for {storage_name}: {str(e)}")
                        
        except Exception as e:
            logger.debug(f"Azure storage check failed for {domain}: {str(e)}")
    
    async def _check_gcp_storage(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for public GCP storage"""
        try:
            # Common bucket naming patterns
            bucket_names = [
                domain,
                domain.replace('.', '-'),
                f"{domain}-backup",
                f"{domain}-logs",
                f"www-{domain}"
            ]
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for bucket_name in bucket_names:
                    try:
                        gcp_url = f"https://storage.googleapis.com/{bucket_name}"
                        
                        # SECURITY: Validate URL before making request
                        try:
                            sanitized_url = validate_external_url(gcp_url)
                            gcp_url = sanitized_url
                        except ValueError:
                            continue
                        
                        response = await client.get(gcp_url)
                        
                        if response.status_code == 200:
                            # Bucket is publicly accessible
                            result.gcp_storage_public.append(bucket_name)
                            result.public_cloud_resources.append(f"GCP Storage: {bucket_name}")
                            result.security_issues.append(f"Public GCP storage found: {bucket_name}")
                            
                    except Exception as e:
                        logger.debug(f"GCP storage test failed for {bucket_name}: {str(e)}")
                        
        except Exception as e:
            logger.debug(f"GCP storage check failed for {domain}: {str(e)}")
    
    async def _analyze_cdn_configuration(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Analyze CDN configuration and security"""
        try:
            logger.debug(f"Analyzing CDN configuration for {domain}")
            
            for asset in assets:
                headers = asset.headers
                
                # Detect CDN provider
                for cdn, indicators in self.cdn_providers.items():
                    for indicator in indicators:
                        if any(indicator.lower() in f"{k.lower()}: {v.lower()}" for k, v in headers.items()):
                            result.cdn_provider = cdn
                            break
                    if result.cdn_provider:
                        break
                
                # Check for CDN security issues
                if result.cdn_provider:
                    # Check for cache poisoning risks
                    if 'vary' not in [h.lower() for h in headers.keys()]:
                        result.cdn_misconfigurations.append("Missing Vary header - potential cache poisoning risk")
                    
                    # Check for cache control
                    cache_control = headers.get('cache-control', '').lower()
                    if 'no-cache' not in cache_control and 'private' not in cache_control:
                        # Check if sensitive content might be cached
                        if any(keyword in asset.domain for keyword in ['admin', 'api', 'auth']):
                            result.cdn_misconfigurations.append("Potentially sensitive content being cached")
                    
                    # Check for origin exposure
                    origin_header = headers.get('x-forwarded-for', '')
                    if origin_header:
                        result.cdn_misconfigurations.append("Origin server IP potentially exposed")
            
        except Exception as e:
            logger.debug(f"CDN analysis failed for {domain}: {str(e)}")
    
    async def _check_cloud_misconfigurations(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for common cloud misconfigurations"""
        try:
            logger.debug(f"Checking cloud misconfigurations for {domain}")
            
            # Check for exposed configuration files
            config_files = [
                '.aws/credentials',
                '.azure/credentials',
                'gcp-key.json',
                'aws-credentials.json',
                'azure-credentials.json',
                'terraform.tfstate',
                'cloudformation.json'
            ]
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for asset in assets:
                    base_url = f"{asset.protocol}://{asset.domain}:{asset.port}"
                    
                    for config_file in config_files:
                        try:
                            config_url = f"{base_url}/{config_file}"
                            
                            # SECURITY: Validate URL before making request
                            try:
                                sanitized_url = validate_external_url(config_url)
                                config_url = sanitized_url
                            except ValueError:
                                continue
                            
                            response = await client.get(config_url)
                            
                            if response.status_code == 200:
                                result.insecure_cloud_configs.append(config_file)
                                result.security_issues.append(f"Exposed cloud configuration: {config_file}")
                                
                        except Exception as e:
                            logger.debug(f"Config file test failed for {config_file}: {str(e)}")
            
        except Exception as e:
            logger.debug(f"Cloud misconfiguration check failed for {domain}: {str(e)}")
    
    async def _check_metadata_exposure(self, domain: str, assets: List[Asset], result: CloudSecurityResult):
        """Check for exposed cloud metadata"""
        try:
            logger.debug(f"Checking metadata exposure for {domain}")
            
            # Cloud metadata endpoints
            metadata_endpoints = [
                'http://169.254.169.254/metadata/instance',  # Azure
                'http://169.254.169.254/latest/meta-data/',   # AWS
                'http://metadata.google.internal/computeMetadata/v1/'  # GCP
            ]
            
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                for endpoint in metadata_endpoints:
                    try:
                        # Note: This would only work if testing from within cloud environment
                        # Included for completeness but will likely timeout
                        response = await client.get(endpoint, headers={'Metadata': 'true'})
                        
                        if response.status_code == 200:
                            result.cloud_metadata_exposed = True
                            result.security_issues.append("Cloud metadata service accessible")
                            
                    except Exception:
                        # Expected to fail from external networks
                        pass
            
        except Exception as e:
            logger.debug(f"Metadata exposure check failed for {domain}: {str(e)}")
    
    def _calculate_cloud_security_score(self, result: CloudSecurityResult):
        """Calculate cloud security score (0-100)"""
        score = 100.0
        
        # Public resources penalty (40 points)
        public_resource_penalty = min(40, len(result.public_cloud_resources) * 20)
        score -= public_resource_penalty
        
        # Insecure configurations penalty (30 points)
        config_penalty = min(30, len(result.insecure_cloud_configs) * 15)
        score -= config_penalty
        
        # CDN misconfigurations penalty (20 points)
        cdn_penalty = min(20, len(result.cdn_misconfigurations) * 5)
        score -= cdn_penalty
        
        # Metadata exposure penalty (10 points)
        if result.cloud_metadata_exposed:
            score -= 10
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.cloud_security_score = score
    
    def _generate_cloud_recommendations(self, result: CloudSecurityResult):
        """Generate cloud security recommendations"""
        recommendations = []
        
        # Public resources recommendations
        if result.public_cloud_resources:
            recommendations.append("Secure or remove publicly accessible cloud resources")
            recommendations.append("Implement proper access controls and bucket policies")
            recommendations.append("Enable logging and monitoring for cloud resources")
        
        if result.s3_buckets_public:
            recommendations.append("Configure S3 bucket policies to prevent public access")
            recommendations.append("Enable S3 Block Public Access settings")
        
        if result.azure_storage_public:
            recommendations.append("Configure Azure Storage access policies")
            recommendations.append("Use private endpoints for Azure Storage")
        
        if result.gcp_storage_public:
            recommendations.append("Configure GCP IAM policies for Cloud Storage")
            recommendations.append("Use uniform bucket-level access controls")
        
        # Configuration recommendations
        if result.insecure_cloud_configs:
            recommendations.append("Remove exposed cloud configuration files")
            recommendations.append("Use secure methods to store cloud credentials")
            recommendations.append("Implement proper secrets management")
        
        # CDN recommendations
        if result.cdn_misconfigurations:
            recommendations.append("Review and secure CDN configuration")
            recommendations.append("Implement proper cache controls for sensitive content")
            recommendations.append("Hide origin server information")
        
        # Metadata recommendations
        if result.cloud_metadata_exposed:
            recommendations.append("Restrict access to cloud metadata services")
            recommendations.append("Implement network segmentation")
        
        # General recommendations
        if result.cloud_security_score < 80:
            recommendations.append("Implement cloud security monitoring and alerting")
            recommendations.append("Regular cloud security assessments and audits")
            recommendations.append("Follow cloud provider security best practices")
        
        result.recommendations = recommendations 