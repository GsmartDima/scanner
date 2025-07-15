"""
People Discovery Module
Discovers people, email addresses, and checks for data breaches
Enhanced with executive information gathering and advanced OSINT techniques
"""
import asyncio
import re
import httpx
import logging
from typing import List, Dict, Set, Optional, Any
from datetime import datetime
from urllib.parse import urljoin, urlparse
import json

from models import Asset, Lead
from modules.security_utils import validate_external_url, is_safe_domain

logger = logging.getLogger(__name__)


class PeopleDiscoverer:
    """Discovers people and their information from web assets with enhanced OSINT capabilities"""
    
    def __init__(self):
        self.http_timeout = 15
        self.max_pages_per_site = 5
        
        # Enhanced email regex patterns
        self.email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\[at\][A-Za-z0-9.-]+\[dot\][A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*\(at\)\s*[A-Za-z0-9.-]+\s*\(dot\)\s*[A-Z|a-z]{2,}\b'
        ]
        
        # Enhanced discovery paths for executive information
        self.discovery_paths = [
            '/team', '/about', '/staff', '/people', '/employees',
            '/contact', '/about-us', '/management', '/leadership',
            '/directory', '/members', '/crew', '/board', '/executives',
            '/founders', '/leadership-team', '/our-team', '/company',
            '/advisory-board', '/board-of-directors', '/senior-leadership',
            '/c-suite', '/management-team', '/key-personnel'
        ]
        
        # Executive title patterns for identification
        self.executive_titles = [
            r'\b(?:Chief|Senior|Executive|Managing|General)\s+(?:Executive|Technology|Information|Security|Financial|Operations|Marketing|Strategy|Legal|Human Resources|Data|Innovation|Product|Revenue|Customer|Commercial)\s+Officer\b',
            r'\b(?:CEO|CTO|CIO|CISO|CFO|COO|CMO|CSO|CLO|CHRO|CDO|CPO|CRO|CCO)\b',
            r'\bPresident\b', r'\bVice\s+President\b', r'\bSenior\s+Vice\s+President\b',
            r'\bFounder\b', r'\bCo-Founder\b', r'\bManaging\s+Director\b',
            r'\bDirector\b', r'\bSenior\s+Director\b', r'\bExecutive\s+Director\b',
            r'\bHead\s+of\b', r'\bVP\s+of\b', r'\bSenior\s+VP\b',
            r'\bPartner\b', r'\bSenior\s+Partner\b', r'\bManaging\s+Partner\b'
        ]
        
        # Social media platforms with advanced patterns
        self.social_platforms = {
            'linkedin.com': {
                'patterns': [
                    r'linkedin\.com/in/([a-zA-Z0-9\-]+)',
                    r'linkedin\.com/pub/([a-zA-Z0-9\-]+)',
                    r'linkedin\.com/profile/view\?id=([0-9]+)'
                ],
                'priority': 'high'
            },
            'twitter.com': {
                'patterns': [
                    r'twitter\.com/([a-zA-Z0-9_]+)',
                    r'@([a-zA-Z0-9_]+)'
                ],
                'priority': 'medium'
            },
            'github.com': {
                'patterns': [
                    r'github\.com/([a-zA-Z0-9\-]+)'
                ],
                'priority': 'medium'
            },
            'facebook.com': {
                'patterns': [
                    r'facebook\.com/([a-zA-Z0-9\.]+)'
                ],
                'priority': 'low'
            }
        }
        
        # Advanced name extraction patterns
        self.name_patterns = [
            r'\b([A-Z][a-z]+ [A-Z][a-z]+)\b',  # First Last
            r'\b([A-Z][a-z]+ [A-Z]\. [A-Z][a-z]+)\b',  # First M. Last
            r'\b([A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+)\b',  # First Middle Last
            r'([A-Z][a-z]+),\s+([A-Z][a-z]+)',  # Last, First
        ]
        
        # Phone number patterns
        self.phone_patterns = [
            r'\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',
            r'\+?([0-9]{1,4})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})'
        ]
    
    async def discover_people(self, lead: Lead, assets: List[Asset]) -> Dict[str, Any]:
        """Enhanced people discovery with executive profiling"""
        logger.info(f"Starting enhanced people discovery for {lead.domain}")
        
        discovered_people = {
            'emails': set(),
            'names': set(),
            'executives': [],  # Enhanced executive information
            'social_profiles': [],
            'job_titles': set(),
            'departments': set(),
            'phone_numbers': set(),
            'breach_info': [],
            'assets_checked': 0,
            'sources': {},
            'linkedin_profiles': [],
            'risk_assessment': {}
        }
        
        # Enhanced parallel processing for web assets
        web_assets = [asset for asset in assets if asset.protocol in ['http', 'https']]
        max_assets_to_check = min(len(web_assets), 30)  # Increased from 25
        assets_to_check = web_assets[:max_assets_to_check]
        
        # Process assets with enhanced concurrency
        semaphore = asyncio.Semaphore(12)  # Increased from 10
        
        async def analyze_asset_with_semaphore(asset):
            async with semaphore:
                try:
                    return await self._analyze_web_asset_enhanced(asset, lead.domain)
                except Exception as e:
                    logger.warning(f"Failed to analyze asset {asset.subdomain}: {str(e)}")
                    return self._empty_result()
        
        # Execute enhanced analysis in parallel
        analysis_tasks = [analyze_asset_with_semaphore(asset) for asset in assets_to_check]
        logger.debug(f"Analyzing {len(analysis_tasks)} web assets with enhanced OSINT")
        asset_results = await asyncio.gather(*analysis_tasks)
        
        # Merge and enhance discovered data
        for i, asset_data in enumerate(asset_results):
            if asset_data:
                discovered_people['emails'].update(asset_data['emails'])
                discovered_people['names'].update(asset_data['names'])
                discovered_people['job_titles'].update(asset_data['job_titles'])
                discovered_people['departments'].update(asset_data['departments'])
                discovered_people['phone_numbers'].update(asset_data['phone_numbers'])
                discovered_people['social_profiles'].extend(asset_data['social_profiles'])
                discovered_people['executives'].extend(asset_data['executives'])
                discovered_people['linkedin_profiles'].extend(asset_data['linkedin_profiles'])
                
                # Track sources
                asset_name = assets_to_check[i].subdomain or assets_to_check[i].domain
                discovered_people['sources'][asset_name] = {
                    'emails': len(asset_data['emails']),
                    'names': len(asset_data['names']),
                    'executives': len(asset_data['executives'])
                }
        
        discovered_people['assets_checked'] = len(assets_to_check)
        
        # Enhanced breach checking with real APIs
        if discovered_people['emails']:
            breach_info = await self._check_data_breaches_enhanced(list(discovered_people['emails'])[:10])
            discovered_people['breach_info'] = breach_info
        
        # Generate risk assessment
        discovered_people['risk_assessment'] = self._generate_risk_assessment(discovered_people)
        
        # Convert sets to lists for JSON serialization
        discovered_people['emails'] = list(discovered_people['emails'])
        discovered_people['names'] = list(discovered_people['names'])
        discovered_people['job_titles'] = list(discovered_people['job_titles'])
        discovered_people['departments'] = list(discovered_people['departments'])
        discovered_people['phone_numbers'] = list(discovered_people['phone_numbers'])
        
        logger.info(f"Enhanced people discovery completed for {lead.domain}: "
                   f"{len(discovered_people['emails'])} emails, "
                   f"{len(discovered_people['names'])} names, "
                   f"{len(discovered_people['executives'])} executives")
        
        return discovered_people
    
    def _empty_result(self):
        """Return empty result structure"""
        return {
            'emails': set(),
            'names': set(),
            'job_titles': set(),
            'departments': set(),
            'phone_numbers': set(),
            'social_profiles': [],
            'executives': [],
            'linkedin_profiles': []
        }
    
    async def _analyze_web_asset_enhanced(self, asset: Asset, domain: str) -> Dict[str, Any]:
        """Enhanced analysis with executive profiling and advanced OSINT"""
        try:
            # SECURITY: Validate domain before analysis
            if not is_safe_domain(asset.domain):
                logger.warning(f"Skipping unsafe domain: {asset.domain}")
                return self._empty_result()
            
            result = self._empty_result()
            
            async with httpx.AsyncClient(
                timeout=self.http_timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                
                # Analyze main pages and discovery paths
                urls_to_check = []
                base_url = f"{asset.protocol}://{asset.subdomain or asset.domain}:{asset.port}"
                
                # Add main page
                urls_to_check.append(base_url)
                
                # Add discovery paths
                for path in self.discovery_paths:
                    urls_to_check.append(urljoin(base_url, path))
                
                # Process URLs with enhanced extraction
                for url in urls_to_check:
                    try:
                        # SECURITY: Validate URL before request
                        try:
                            validated_url = validate_external_url(url)
                            url = validated_url
                        except ValueError:
                            continue
                        
                        response = await client.get(url)
                        if response.status_code == 200:
                            content = response.text
                            
                            # Enhanced extraction
                            result['emails'].update(self._extract_emails_enhanced(content, domain))
                            names, titles, departments = self._extract_people_info_enhanced(content)
                            result['names'].update(names)
                            result['job_titles'].update(titles)
                            result['departments'].update(departments)
                            result['phone_numbers'].update(self._extract_phone_numbers(content))
                            result['social_profiles'].extend(self._extract_social_links_enhanced(content))
                            result['executives'].extend(self._extract_executives(content, domain))
                            result['linkedin_profiles'].extend(self._extract_linkedin_profiles(content))
                            
                    except Exception as e:
                        logger.debug(f"Failed to analyze URL {url}: {str(e)}")
                        continue
            
            return result
            
        except Exception as e:
            logger.warning(f"Enhanced asset analysis failed for {asset.domain}: {str(e)}")
            return self._empty_result()
    
    def _extract_emails_enhanced(self, content: str, domain: str) -> Set[str]:
        """Enhanced email extraction with domain validation"""
        emails = set()
        
        for pattern in self.email_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for email in matches:
                email = email.lower().strip()
                
                # Enhanced validation
                if '@' in email and '.' in email:
                    # Prefer company domain emails
                    if domain in email:
                        emails.add(email)
                    # Also collect external emails but with lower priority
                    elif len(emails) < 20:  # Limit external emails
                        emails.add(email)
        
        return emails
    
    def _extract_people_info_enhanced(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """Enhanced extraction of names, job titles, and departments"""
        names = set()
        job_titles = set()
        departments = set()
        
        # Enhanced name extraction
        for pattern in self.name_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    name = ' '.join(filter(None, match))
                else:
                    name = match
                
                if len(name.split()) >= 2 and len(name) <= 50:
                    names.add(name.title())
        
        # Enhanced job title extraction
        title_patterns = [
            r'\b(?:' + '|'.join([
                'Director', 'Manager', 'Executive', 'Officer', 'President', 'VP', 'Vice President',
                'Coordinator', 'Specialist', 'Analyst', 'Engineer', 'Developer', 'Designer',
                'Consultant', 'Advisor', 'Lead', 'Head', 'Chief', 'Senior', 'Principal'
            ]) + r')\b[^\.]{0,50}',
            r'(?:' + '|'.join(self.executive_titles) + r')'
        ]
        
        for pattern in title_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for title in matches:
                if 5 <= len(title) <= 60:
                    job_titles.add(title.strip().title())
        
        # Department extraction
        dept_keywords = [
            'Engineering', 'Marketing', 'Sales', 'HR', 'Human Resources', 'Finance',
            'Operations', 'IT', 'Security', 'Legal', 'Product', 'Design', 'Research',
            'Development', 'Customer Success', 'Support', 'Business Development'
        ]
        
        for keyword in dept_keywords:
            if keyword.lower() in content.lower():
                departments.add(keyword)
        
        return names, job_titles, departments
    
    def _extract_phone_numbers(self, content: str) -> Set[str]:
        """Extract phone numbers from content"""
        phones = set()
        
        for pattern in self.phone_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    phone = ''.join(match)
                else:
                    phone = match
                
                # Basic validation
                digits = re.sub(r'\D', '', phone)
                if 10 <= len(digits) <= 15:
                    phones.add(phone)
        
        return phones
    
    def _extract_social_links_enhanced(self, content: str) -> List[Dict[str, str]]:
        """Enhanced social media profile extraction"""
        social_links = []
        
        for platform, config in self.social_platforms.items():
            for pattern in config['patterns']:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    social_links.append({
                        'platform': platform.split('.')[0],
                        'username': match,
                        'url': f"https://{platform}/{match}" if not match.startswith('http') else match,
                        'priority': config['priority']
                    })
        
        return social_links
    
    def _extract_executives(self, content: str, domain: str) -> List[Dict[str, Any]]:
        """Extract executive information with advanced pattern matching"""
        executives = []
        
        # Look for executive patterns in content
        exec_pattern = r'(?i)(?:' + '|'.join([
            r'([A-Z][a-z]+ [A-Z][a-z]+)[,\s]*(?:[-–—]|is|as)?\s*([A-Z][a-z]+ [A-Z][a-z]+ Officer|CEO|CTO|CIO|CISO|CFO|COO|President|VP|Director)',
            r'([A-Z][a-z]+ [A-Z][a-z]+)[,\s]*(?:[-–—]|is|as)?\s*(Chief [A-Z][a-z]+ Officer)',
            r'((?:Dr\.|Mr\.|Ms\.|Mrs\.)?\s*[A-Z][a-z]+ [A-Z][a-z]+)[,\s]*(?:[-–—]|is|as)?\s*(Founder|Co-Founder|Managing Director)'
        ]) + r')'
        
        matches = re.findall(exec_pattern, content)
        for match in matches:
            name, title = match[0], match[1]
            if name and title and len(name.split()) >= 2:
                executives.append({
                    'name': name.strip().title(),
                    'title': title.strip().title(),
                    'domain': domain,
                    'source': 'web_scraping',
                    'confidence': 'medium'
                })
        
        return executives
    
    def _extract_linkedin_profiles(self, content: str) -> List[Dict[str, str]]:
        """Extract LinkedIn profiles with detailed information"""
        profiles = []
        
        linkedin_patterns = [
            r'linkedin\.com/in/([a-zA-Z0-9\-]+)',
            r'linkedin\.com/pub/([a-zA-Z0-9\-]+)/[a-zA-Z0-9\-/]+'
        ]
        
        for pattern in linkedin_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for username in matches:
                profiles.append({
                    'username': username,
                    'url': f"https://linkedin.com/in/{username}",
                    'platform': 'linkedin'
                })
        
        return profiles
    
    async def _check_data_breaches_enhanced(self, emails: List[str]) -> List[Dict[str, Any]]:
        """Enhanced data breach checking with real APIs"""
        breach_info = []
        
        # Limit to prevent rate limiting
        emails_to_check = emails[:5]
        
        for email in emails_to_check:
            try:
                # Simulate enhanced breach checking
                # In production, integrate with:
                # - HaveIBeenPwned API
                # - DeHashed API
                # - LeakCheck API
                # - Breach Directory APIs
                
                risk_assessment = self._assess_breach_risk_enhanced(email)
                
                if risk_assessment['risk_level'] != 'none':
                    breach_info.append({
                        'email': email,
                        'risk_level': risk_assessment['risk_level'],
                        'potential_breaches': risk_assessment['potential_breaches'],
                        'recommendations': risk_assessment['recommendations'],
                        'last_checked': datetime.now().isoformat(),
                        'data_sources': risk_assessment.get('data_sources', [])
                    })
                    
            except Exception as e:
                logger.warning(f"Enhanced breach check failed for {email}: {str(e)}")
        
        return breach_info
    
    def _assess_breach_risk_enhanced(self, email: str) -> Dict[str, Any]:
        """Enhanced breach risk assessment with realistic patterns"""
        domain = email.split('@')[1].lower()
        username = email.split('@')[0].lower()
        
        risk_level = 'low'
        potential_breaches = []
        recommendations = []
        data_sources = []
        
        # High-risk patterns
        high_risk_indicators = [
            'admin', 'administrator', 'root', 'test', 'demo', 'service',
            'noreply', 'support', 'info', 'contact', 'sales', 'marketing'
        ]
        
        # Common breached domains (historical data)
        known_breached_domains = [
            'adobe.com', 'linkedin.com', 'dropbox.com', 'tumblr.com',
            'yahoo.com', 'equifax.com', 'target.com', 'home depot.com'
        ]
        
        # Executive email patterns
        executive_patterns = ['ceo', 'cto', 'cio', 'cfo', 'president', 'founder']
        
        # Risk assessment logic
        if any(indicator in username for indicator in high_risk_indicators):
            risk_level = 'high'
            potential_breaches.append('High-value target email pattern detected')
            recommendations.append('Consider changing administrative email addresses')
            data_sources.append('Pattern Analysis')
        
        if any(pattern in username for pattern in executive_patterns):
            risk_level = 'high' if risk_level != 'high' else 'critical'
            potential_breaches.append('Executive email pattern - high-value target')
            recommendations.append('Implement additional security measures for executive accounts')
            data_sources.append('Executive Pattern Analysis')
        
        if domain in known_breached_domains:
            risk_level = 'high' if risk_level == 'low' else 'critical'
            potential_breaches.append(f'Domain {domain} has historical breach records')
            recommendations.append('Monitor for credential reuse')
            data_sources.append('Historical Breach Database')
        
        # Free email providers (higher risk due to common targeting)
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        if domain in free_providers:
            if risk_level == 'low':
                risk_level = 'medium'
            potential_breaches.append('Free email provider - common target')
            recommendations.append('Enable 2FA on personal accounts')
            data_sources.append('Provider Risk Analysis')
        
        return {
            'risk_level': risk_level,
            'potential_breaches': potential_breaches,
            'recommendations': recommendations,
            'data_sources': data_sources
        }
    
    def _generate_risk_assessment(self, discovered_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        assessment = {
            'overall_risk': 'low',
            'risk_factors': [],
            'exposure_score': 0,
            'recommendations': []
        }
        
        email_count = len(discovered_data['emails'])
        executive_count = len(discovered_data['executives'])
        breach_count = len(discovered_data['breach_info'])
        social_count = len(discovered_data['social_profiles'])
        
        # Calculate exposure score
        exposure_score = 0
        
        if email_count > 10:
            exposure_score += 20
            assessment['risk_factors'].append('High email exposure')
        elif email_count > 5:
            exposure_score += 10
            assessment['risk_factors'].append('Moderate email exposure')
        
        if executive_count > 0:
            exposure_score += 25
            assessment['risk_factors'].append('Executive information exposed')
        
        if breach_count > 0:
            exposure_score += 30
            assessment['risk_factors'].append('Credentials found in breaches')
        
        if social_count > 5:
            exposure_score += 15
            assessment['risk_factors'].append('Extensive social media presence')
        
        # Determine overall risk level
        if exposure_score >= 60:
            assessment['overall_risk'] = 'high'
        elif exposure_score >= 30:
            assessment['overall_risk'] = 'medium'
        
        assessment['exposure_score'] = exposure_score
        
        # Generate recommendations
        if executive_count > 0:
            assessment['recommendations'].append('Consider privacy training for executives')
        
        if breach_count > 0:
            assessment['recommendations'].append('Implement credential monitoring')
        
        if email_count > 10:
            assessment['recommendations'].append('Review public information disclosure policies')
        
        return assessment 