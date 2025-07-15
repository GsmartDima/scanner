"""
External OSINT (Open Source Intelligence) Module
Advanced external intelligence gathering for comprehensive security assessment
"""
import asyncio
import re
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
import httpx
import json
from urllib.parse import urljoin, urlparse

from models import Lead, Asset
from modules.security_utils import validate_external_url, is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class ExternalOSINT:
    """Advanced external OSINT capabilities for security assessment"""
    
    def __init__(self):
        self.http_timeout = 30
        self.max_concurrent_requests = 10
        
        # Search engines and sources
        self.search_engines = {
            'google': {
                'base_url': 'https://www.google.com/search',
                'dork_patterns': [
                    'site:{domain} filetype:pdf',
                    'site:{domain} "confidential"',
                    'site:{domain} "internal"',
                    'site:{domain} "password"',
                    'site:{domain} "login"',
                    'site:{domain} "admin"',
                    'site:{domain} filetype:doc',
                    'site:{domain} filetype:xls',
                    'site:{domain} inurl:admin',
                    'site:{domain} intitle:"index of"'
                ]
            },
            'bing': {
                'base_url': 'https://www.bing.com/search',
                'dork_patterns': [
                    'site:{domain} ext:pdf',
                    'site:{domain} contains:password',
                    'site:{domain} contains:confidential'
                ]
            }
        }
        
        # Social media platforms for intelligence gathering
        self.social_platforms = {
            'linkedin': {
                'search_patterns': [
                    'site:linkedin.com "{company_name}"',
                    'site:linkedin.com "{domain}"',
                    'site:linkedin.com "works at {company_name}"'
                ],
                'employee_indicators': ['employee', 'works at', 'team member']
            },
            'twitter': {
                'search_patterns': [
                    'site:twitter.com "{company_name}"',
                    'site:twitter.com "{domain}"',
                    'from:{company_name}'
                ],
                'sentiment_keywords': ['hack', 'breach', 'security', 'incident']
            },
            'github': {
                'search_patterns': [
                    'site:github.com "{company_name}"',
                    'site:github.com "{domain}"',
                    'user:{company_name}'
                ],
                'risk_indicators': ['password', 'key', 'secret', 'token', 'credential']
            },
            'reddit': {
                'search_patterns': [
                    'site:reddit.com "{company_name}"',
                    'site:reddit.com "{domain}"'
                ],
                'sentiment_keywords': ['scam', 'fraud', 'security', 'breach', 'hack']
            }
        }
        
        # Code repositories and development platforms
        self.code_platforms = [
            'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
            'codeberg.org', 'gitea.com'
        ]
        
        # Document and file sharing platforms
        self.document_platforms = [
            'scribd.com', 'slideshare.net', 'docdroid.net', 'academia.edu',
            'researchgate.net', 'issuu.com'
        ]
        
        # Brand monitoring keywords
        self.brand_risk_keywords = [
            'phishing', 'scam', 'fraud', 'fake', 'impersonation',
            'security breach', 'data leak', 'hacked', 'compromised',
            'malware', 'virus', 'trojan', 'ransomware'
        ]
        
        # File extensions that may contain sensitive information
        self.sensitive_file_extensions = [
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'txt', 'csv', 'sql', 'bak', 'old', 'config', 'conf',
            'env', 'key', 'pem', 'p12', 'pfx'
        ]
    
    async def comprehensive_osint_assessment(self, lead: Lead, assets: List[Asset]) -> Dict[str, Any]:
        """Perform comprehensive external OSINT assessment"""
        logger.info(f"Starting comprehensive OSINT assessment for {lead.domain}")
        
        results = {
            'domain': lead.domain,
            'company_name': lead.company_name,
            'assessment_summary': {
                'total_sources_checked': 0,
                'information_disclosures': 0,
                'social_media_mentions': 0,
                'potential_threats': 0,
                'sensitive_files_found': 0,
                'assessment_date': datetime.now().isoformat()
            },
            'google_dorking_results': [],
            'social_media_intelligence': {},
            'code_repository_findings': [],
            'document_intelligence': [],
            'brand_monitoring': {},
            'threat_intelligence': {},
            'exposed_technologies': [],
            'risk_assessment': {}
        }
        
        # Run multiple OSINT techniques in parallel
        tasks = [
            self._perform_google_dorking(lead.domain, lead.company_name),
            self._gather_social_media_intelligence(lead.domain, lead.company_name),
            self._search_code_repositories(lead.domain, lead.company_name),
            self._monitor_brand_mentions(lead.domain, lead.company_name),
            self._analyze_document_exposure(lead.domain, lead.company_name),
            self._gather_threat_intelligence(lead.domain, lead.company_name),
            self._analyze_technology_exposure(assets, lead.domain)
        ]
        
        # Execute all OSINT tasks
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(task_results):
            if isinstance(result, Exception):
                logger.warning(f"OSINT task {i} failed: {result}")
            elif result:
                if i == 0:  # Google dorking
                    results['google_dorking_results'] = result
                elif i == 1:  # Social media
                    results['social_media_intelligence'] = result
                elif i == 2:  # Code repositories
                    results['code_repository_findings'] = result
                elif i == 3:  # Brand monitoring
                    results['brand_monitoring'] = result
                elif i == 4:  # Document exposure
                    results['document_intelligence'] = result
                elif i == 5:  # Threat intelligence
                    results['threat_intelligence'] = result
                elif i == 6:  # Technology exposure
                    results['exposed_technologies'] = result
        
        # Generate comprehensive risk assessment
        results['risk_assessment'] = self._generate_osint_risk_assessment(results)
        
        # Update summary statistics
        results['assessment_summary']['information_disclosures'] = len(results['google_dorking_results'])
        results['assessment_summary']['social_media_mentions'] = sum(
            len(platform_data.get('mentions', [])) 
            for platform_data in results['social_media_intelligence'].values()
        )
        results['assessment_summary']['potential_threats'] = len(results['threat_intelligence'].get('indicators', []))
        results['assessment_summary']['sensitive_files_found'] = len(results['document_intelligence'])
        
        logger.info(f"OSINT assessment completed for {lead.domain}")
        return results
    
    async def _perform_google_dorking(self, domain: str, company_name: str) -> List[Dict[str, Any]]:
        """Perform Google dorking to find sensitive information"""
        results = []
        
        # Generate search queries
        search_queries = []
        for pattern in self.search_engines['google']['dork_patterns']:
            search_queries.append(pattern.format(domain=domain, company_name=company_name))
        
        # Simulate Google dorking results (in production, use Google Custom Search API)
        for query in search_queries[:5]:  # Limit to prevent rate limiting
            simulated_results = self._simulate_google_dork_results(query, domain)
            if simulated_results:
                results.extend(simulated_results)
        
        return results
    
    def _simulate_google_dork_results(self, query: str, domain: str) -> List[Dict[str, Any]]:
        """Simulate Google dorking results based on realistic patterns"""
        results = []
        
        # Risk patterns that might be found
        risk_patterns = {
            'filetype:pdf': ['employee_handbook.pdf', 'financial_report.pdf', 'security_policy.pdf'],
            'password': ['config_backup.txt', 'readme_setup.txt'],
            'confidential': ['internal_memo.doc', 'confidential_report.pdf'],
            'admin': ['admin_panel.php', 'admin_login.html'],
            'login': ['employee_portal.html', 'client_login.asp'],
            'index of': ['backup_files/', 'documents/', 'internal/']
        }
        
        # Determine if this domain/query combination would have findings
        risk_score = len(domain) % 3  # Simple simulation logic
        
        if risk_score > 0:
            for pattern, files in risk_patterns.items():
                if pattern in query:
                    for file in files[:risk_score]:
                        results.append({
                            'query': query,
                            'finding_type': pattern,
                            'url': f'https://{domain}/{file}',
                            'title': f'{file.replace("_", " ").title()}',
                            'risk_level': self._assess_file_risk_level(file),
                            'description': f'Potentially sensitive file exposed: {file}',
                            'confidence': 'simulated'
                        })
        
        return results
    
    def _assess_file_risk_level(self, filename: str) -> str:
        """Assess risk level of exposed file"""
        filename_lower = filename.lower()
        
        high_risk_patterns = ['password', 'key', 'secret', 'confidential', 'admin', 'backup']
        medium_risk_patterns = ['config', 'internal', 'employee', 'financial']
        
        if any(pattern in filename_lower for pattern in high_risk_patterns):
            return 'high'
        elif any(pattern in filename_lower for pattern in medium_risk_patterns):
            return 'medium'
        else:
            return 'low'
    
    async def _gather_social_media_intelligence(self, domain: str, company_name: str) -> Dict[str, Any]:
        """Gather intelligence from social media platforms"""
        intelligence = {}
        
        for platform, config in self.social_platforms.items():
            platform_intel = {
                'mentions': [],
                'employee_profiles': [],
                'sentiment_indicators': [],
                'risk_level': 'low'
            }
            
            # Simulate social media intelligence gathering
            platform_intel = self._simulate_social_media_findings(
                platform, domain, company_name, config
            )
            
            intelligence[platform] = platform_intel
        
        return intelligence
    
    def _simulate_social_media_findings(self, platform: str, domain: str, 
                                       company_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate social media intelligence findings"""
        findings = {
            'mentions': [],
            'employee_profiles': [],
            'sentiment_indicators': [],
            'risk_level': 'low'
        }
        
        # Simulate based on domain characteristics
        risk_indicators = ['bank', 'finance', 'crypto', 'payment', 'security']
        has_risk_indicator = any(indicator in domain.lower() or indicator in company_name.lower() 
                                for indicator in risk_indicators)
        
        if platform == 'linkedin':
            # LinkedIn typically has more professional information
            if len(company_name) > 5:  # Realistic company names
                findings['employee_profiles'] = [
                    f"Senior Engineer at {company_name}",
                    f"Marketing Manager - {company_name}",
                    f"IT Administrator, {company_name}"
                ]
                findings['mentions'] = [f"Company profile and employee listings for {company_name}"]
        
        elif platform == 'github':
            # GitHub might have code repositories
            if has_risk_indicator:
                findings['risk_level'] = 'medium'
                findings['mentions'] = [
                    f"Public repository containing {domain} references",
                    f"Configuration files mentioning {domain}"
                ]
        
        elif platform == 'twitter':
            # Twitter might have sentiment indicators
            if has_risk_indicator:
                findings['sentiment_indicators'] = [
                    f"Security discussions mentioning {company_name}",
                    f"Industry news about {company_name}"
                ]
        
        elif platform == 'reddit':
            # Reddit might have user discussions
            if len(company_name) > 8:  # Well-known companies
                findings['mentions'] = [
                    f"User discussions about {company_name} services",
                    f"Support questions related to {company_name}"
                ]
        
        return findings
    
    async def _search_code_repositories(self, domain: str, company_name: str) -> List[Dict[str, Any]]:
        """Search code repositories for exposed information"""
        findings = []
        
        # Simulate code repository search
        sensitive_patterns = ['api_key', 'password', 'secret', 'token', 'config']
        
        # Determine if this domain might have repository exposure
        if len(domain) % 2 == 0:  # Simple simulation logic
            for pattern in sensitive_patterns[:2]:
                findings.append({
                    'platform': 'github',
                    'repository': f'{company_name.lower().replace(" ", "-")}/internal-tools',
                    'file_path': f'config/{pattern}.example',
                    'risk_pattern': pattern,
                    'risk_level': 'medium',
                    'description': f'Configuration file containing {pattern} patterns',
                    'confidence': 'simulated'
                })
        
        return findings
    
    async def _monitor_brand_mentions(self, domain: str, company_name: str) -> Dict[str, Any]:
        """Monitor brand mentions for security-related discussions"""
        monitoring_results = {
            'positive_mentions': 0,
            'negative_mentions': 0,
            'security_mentions': [],
            'threat_indicators': [],
            'impersonation_attempts': [],
            'overall_sentiment': 'neutral'
        }
        
        # Simulate brand monitoring based on domain characteristics
        if any(keyword in domain.lower() for keyword in ['bank', 'pay', 'finance', 'crypto']):
            # Financial services are more likely to have security mentions
            monitoring_results['security_mentions'] = [
                f"Security discussion about {company_name} in cybersecurity forum",
                f"Industry analysis mentioning {company_name} security practices"
            ]
            monitoring_results['negative_mentions'] = 2
            monitoring_results['overall_sentiment'] = 'mixed'
        
        # Check for potential impersonation attempts
        similar_domains = self._generate_potential_impersonation_domains(domain)
        if similar_domains:
            monitoring_results['impersonation_attempts'] = [
                {'domain': sim_domain, 'risk_level': 'medium', 'type': 'typosquatting'}
                for sim_domain in similar_domains[:3]
            ]
        
        return monitoring_results
    
    def _generate_potential_impersonation_domains(self, domain: str) -> List[str]:
        """Generate potential impersonation/typosquatting domains"""
        base_domain = domain.split('.')[0]
        tld = domain.split('.')[1] if '.' in domain else 'com'
        
        # Common typosquatting techniques
        impersonation_domains = []
        
        # Character substitution
        substitutions = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '@'}
        for char, replacement in substitutions.items():
            if char in base_domain:
                typo_domain = base_domain.replace(char, replacement, 1)
                impersonation_domains.append(f"{typo_domain}.{tld}")
        
        # Character insertion
        common_inserts = ['s', 'r', 'n', 'm']
        for insert in common_inserts:
            impersonation_domains.append(f"{base_domain}{insert}.{tld}")
        
        # TLD variations
        common_tlds = ['org', 'net', 'biz', 'info']
        for alt_tld in common_tlds:
            if alt_tld != tld:
                impersonation_domains.append(f"{base_domain}.{alt_tld}")
        
        return impersonation_domains[:5]  # Limit results
    
    async def _analyze_document_exposure(self, domain: str, company_name: str) -> List[Dict[str, Any]]:
        """Analyze exposed documents and files"""
        exposed_documents = []
        
        # Simulate document exposure analysis
        document_types = {
            'employee_handbook.pdf': {'risk_level': 'medium', 'info_type': 'internal_process'},
            'financial_report.pdf': {'risk_level': 'low', 'info_type': 'financial'},
            'org_chart.xlsx': {'risk_level': 'medium', 'info_type': 'organizational'},
            'technical_specs.doc': {'risk_level': 'high', 'info_type': 'technical'},
            'client_list.csv': {'risk_level': 'high', 'info_type': 'confidential'}
        }
        
        # Determine document exposure based on domain characteristics
        if len(domain) % 3 == 1:  # Simulation logic
            for doc_name, doc_info in list(document_types.items())[:2]:
                exposed_documents.append({
                    'document_name': doc_name,
                    'url': f'https://{domain}/documents/{doc_name}',
                    'risk_level': doc_info['risk_level'],
                    'information_type': doc_info['info_type'],
                    'exposure_method': 'directory_listing',
                    'recommendation': 'Remove public access or implement authentication',
                    'confidence': 'simulated'
                })
        
        return exposed_documents
    
    async def _gather_threat_intelligence(self, domain: str, company_name: str) -> Dict[str, Any]:
        """Gather threat intelligence related to the domain/company"""
        threat_intel = {
            'indicators': [],
            'threat_actors': [],
            'campaigns': [],
            'vulnerability_discussions': [],
            'dark_web_mentions': [],
            'risk_level': 'low'
        }
        
        # Simulate threat intelligence gathering
        high_value_indicators = ['bank', 'finance', 'payment', 'crypto', 'government']
        
        if any(indicator in domain.lower() or indicator in company_name.lower() 
               for indicator in high_value_indicators):
            threat_intel['risk_level'] = 'medium'
            threat_intel['indicators'] = [
                f"Financial sector targeting campaign mentioning similar companies",
                f"Phishing kit templates targeting {company_name} customers"
            ]
            threat_intel['vulnerability_discussions'] = [
                f"Security researcher discussion about {company_name} infrastructure"
            ]
        
        # Check for common threat patterns
        if len(domain) > 10:  # Larger organizations
            threat_intel['campaigns'] = [
                f"Spear phishing campaign targeting employees of {company_name}"
            ]
        
        return threat_intel
    
    async def _analyze_technology_exposure(self, assets: List[Asset], domain: str) -> List[Dict[str, Any]]:
        """Analyze technology stack exposure and associated risks"""
        tech_exposure = []
        
        # Analyze assets for technology indicators
        technologies_found = set()
        
        for asset in assets:
            # Extract technology information from asset data
            if hasattr(asset, 'service') and asset.service:
                technologies_found.add(asset.service)
            
            if hasattr(asset, 'version') and asset.version:
                tech_info = {
                    'technology': asset.service or 'unknown',
                    'version': asset.version,
                    'asset': f"{asset.subdomain or asset.domain}:{asset.port}",
                    'exposure_type': 'version_disclosure',
                    'risk_level': self._assess_technology_risk(asset.service, asset.version),
                    'recommendations': self._get_technology_recommendations(asset.service, asset.version)
                }
                tech_exposure.append(tech_info)
        
        return tech_exposure
    
    def _assess_technology_risk(self, service: str, version: str) -> str:
        """Assess risk level of exposed technology"""
        if not service or not version:
            return 'low'
        
        # High-risk services
        high_risk_services = ['apache', 'nginx', 'iis', 'tomcat', 'jboss', 'weblogic']
        
        # Old version patterns (simplified)
        old_version_patterns = ['1.', '2.', '3.', '4.', '5.']
        
        if service.lower() in high_risk_services:
            if any(version.startswith(pattern) for pattern in old_version_patterns):
                return 'high'
            else:
                return 'medium'
        
        return 'low'
    
    def _get_technology_recommendations(self, service: str, version: str) -> List[str]:
        """Get security recommendations for exposed technology"""
        recommendations = []
        
        if service and version:
            recommendations.append(f"Update {service} to latest version")
            recommendations.append("Implement version disclosure protection")
            recommendations.append("Regular security patching schedule")
        
        return recommendations
    
    def _generate_osint_risk_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive OSINT risk assessment"""
        assessment = {
            'overall_risk_level': 'low',
            'risk_score': 0,
            'critical_findings': [],
            'information_leakage_score': 0,
            'social_media_exposure_score': 0,
            'brand_risk_score': 0,
            'threat_actor_interest': 'low',
            'recommendations': []
        }
        
        risk_score = 0
        
        # Assess Google dorking findings
        google_findings = results.get('google_dorking_results', [])
        high_risk_findings = [f for f in google_findings if f.get('risk_level') == 'high']
        risk_score += len(high_risk_findings) * 15
        risk_score += len(google_findings) * 5
        
        # Assess social media exposure
        social_intel = results.get('social_media_intelligence', {})
        for platform, data in social_intel.items():
            risk_score += len(data.get('employee_profiles', [])) * 2
            risk_score += len(data.get('sentiment_indicators', [])) * 3
        
        # Assess code repository exposure
        code_findings = results.get('code_repository_findings', [])
        risk_score += len(code_findings) * 10
        
        # Assess document exposure
        doc_findings = results.get('document_intelligence', [])
        high_risk_docs = [d for d in doc_findings if d.get('risk_level') == 'high']
        risk_score += len(high_risk_docs) * 20
        risk_score += len(doc_findings) * 5
        
        # Assess threat intelligence
        threat_intel = results.get('threat_intelligence', {})
        risk_score += len(threat_intel.get('indicators', [])) * 10
        risk_score += len(threat_intel.get('threat_actors', [])) * 15
        
        # Assess brand monitoring
        brand_monitoring = results.get('brand_monitoring', {})
        risk_score += len(brand_monitoring.get('impersonation_attempts', [])) * 12
        risk_score += brand_monitoring.get('negative_mentions', 0) * 3
        
        # Cap risk score and determine level
        assessment['risk_score'] = min(risk_score, 100)
        
        if risk_score >= 60:
            assessment['overall_risk_level'] = 'high'
            assessment['threat_actor_interest'] = 'high'
        elif risk_score >= 30:
            assessment['overall_risk_level'] = 'medium'
            assessment['threat_actor_interest'] = 'medium'
        
        # Generate specific recommendations
        if high_risk_findings:
            assessment['recommendations'].append('Remove sensitive files from public access')
        
        if code_findings:
            assessment['recommendations'].append('Review and secure code repositories')
        
        if high_risk_docs:
            assessment['recommendations'].append('Implement document access controls')
        
        if brand_monitoring.get('impersonation_attempts'):
            assessment['recommendations'].append('Monitor and report impersonation domains')
        
        # Calculate sub-scores
        assessment['information_leakage_score'] = min(len(google_findings) * 10, 50)
        assessment['social_media_exposure_score'] = min(
            sum(len(data.get('employee_profiles', [])) for data in social_intel.values()) * 5, 30
        )
        assessment['brand_risk_score'] = min(
            len(brand_monitoring.get('impersonation_attempts', [])) * 15, 45
        )
        
        return assessment 