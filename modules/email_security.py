"""
Email Security Assessment Module
Performs comprehensive email security analysis including SPF, DKIM, DMARC validation,
mail server security testing, and email infrastructure assessment.
"""
import asyncio
import dns.resolver
import re
import socket
import logging
import smtplib
from typing import List, Dict, Any, Optional, Tuple
import ssl

from models import EmailSecurityResult, Lead
from modules.security_utils import is_safe_domain
from config import settings

logger = logging.getLogger(__name__)


class EmailSecurityAnalyzer:
    """Email security analyzer"""
    
    def __init__(self):
        self.timeout = 30
        
        # Common DKIM selectors to check
        self.common_dkim_selectors = [
            'default',
            'selector1',
            'selector2',
            'dkim',
            'mail',
            'google',
            'k1',
            's1',
            's2',
            'dk',
            'key1',
            'key2',
            'smtp',
            'email'
        ]
        
        # SPF mechanisms that include all
        self.spf_include_all_patterns = [
            r'[+~-]?all',
            r'include:.*\+all',
            r'redirect=.*\+all'
        ]
        
        # DMARC policy values
        self.dmarc_policies = ['none', 'quarantine', 'reject']
        
        # Mail server ports to test
        self.mail_ports = [25, 465, 587, 993, 995]
    
    async def analyze_email_security(self, leads: List[Lead]) -> List[EmailSecurityResult]:
        """Perform comprehensive email security analysis"""
        logger.info(f"Starting email security analysis for {len(leads)} domains")
        
        results = []
        
        # Analyze each domain with limited concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent email tests
        
        async def limited_analysis(lead):
            async with semaphore:
                return await self._analyze_domain_email_security(lead.domain)
        
        email_results = await asyncio.gather(*[limited_analysis(lead) for lead in leads], 
                                           return_exceptions=True)
        
        # Filter out exceptions and None results
        for i, result in enumerate(email_results):
            if isinstance(result, Exception):
                logger.error(f"Email analysis failed for {leads[i].domain}: {result}")
            elif result:
                results.append(result)
        
        logger.info(f"Completed email security analysis: {len(results)} results")
        return results
    
    async def _analyze_domain_email_security(self, domain: str) -> Optional[EmailSecurityResult]:
        """Analyze email security for a single domain"""
        try:
            # SECURITY: Validate domain before analysis
            if not is_safe_domain(domain):
                logger.warning(f"Skipping email analysis for potentially unsafe domain: {domain}")
                return None
            
            logger.info(f"Analyzing email security for {domain}")
            
            # Create result object
            result = EmailSecurityResult(domain=domain)
            
            # Analyze SPF records
            await self._analyze_spf_record(domain, result)
            
            # Analyze DKIM records
            await self._analyze_dkim_records(domain, result)
            
            # Analyze DMARC records
            await self._analyze_dmarc_record(domain, result)
            
            # Analyze MX records and mail servers
            await self._analyze_mx_records(domain, result)
            
            # Test mail server security
            await self._test_mail_server_security(domain, result)
            
            # Calculate email security score
            self._calculate_email_security_score(result)
            
            # Generate recommendations
            self._generate_email_recommendations(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Email security analysis failed for {domain}: {str(e)}")
            return None
    
    async def _analyze_spf_record(self, domain: str, result: EmailSecurityResult):
        """Analyze SPF (Sender Policy Framework) record"""
        try:
            logger.debug(f"Analyzing SPF record for {domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                # Query for TXT records
                txt_records = resolver.resolve(domain, 'TXT')
                
                for record in txt_records:
                    record_text = str(record).strip('"')
                    
                    # Check if this is an SPF record
                    if record_text.startswith('v=spf1'):
                        result.spf_record = record_text
                        result.spf_valid = True
                        
                        # Analyze SPF policy
                        await self._analyze_spf_policy(record_text, result)
                        break
                
                if not result.spf_record:
                    result.spf_valid = False
                    result.security_issues.append("No SPF record found")
                    
            except dns.resolver.NoAnswer:
                result.spf_valid = False
                result.security_issues.append("No TXT records found for SPF")
            except dns.resolver.NXDOMAIN:
                result.spf_valid = False
                result.security_issues.append("Domain does not exist")
            except Exception as e:
                logger.debug(f"SPF analysis failed for {domain}: {str(e)}")
                result.security_issues.append(f"SPF analysis error: {str(e)}")
                
        except Exception as e:
            logger.debug(f"SPF record analysis failed for {domain}: {str(e)}")
    
    async def _analyze_spf_policy(self, spf_record: str, result: EmailSecurityResult):
        """Analyze SPF policy details"""
        try:
            # Check for +all (allows any server)
            if '+all' in spf_record:
                result.spf_includes_all = True
                result.security_issues.append("SPF record allows all senders (+all)")
            
            # Check for ~all (soft fail) vs -all (hard fail)
            if '~all' in spf_record:
                result.spf_policy = 'softfail'
                result.security_issues.append("SPF uses soft fail (~all) instead of hard fail")
            elif '-all' in spf_record:
                result.spf_policy = 'fail'
            elif '?all' in spf_record:
                result.spf_policy = 'neutral'
                result.security_issues.append("SPF uses neutral policy (?all)")
            else:
                result.spf_policy = 'unknown'
            
            # Count DNS lookups to check for SPF record limits
            include_count = spf_record.count('include:')
            redirect_count = spf_record.count('redirect=')
            a_count = spf_record.count(' a')
            mx_count = spf_record.count(' mx')
            exists_count = spf_record.count('exists:')
            
            total_lookups = include_count + redirect_count + a_count + mx_count + exists_count
            
            if total_lookups > 10:
                result.spf_too_many_lookups = True
                result.security_issues.append(f"SPF record exceeds 10 DNS lookups ({total_lookups})")
            
        except Exception as e:
            logger.debug(f"SPF policy analysis failed: {str(e)}")
    
    async def _analyze_dkim_records(self, domain: str, result: EmailSecurityResult):
        """Analyze DKIM (DomainKeys Identified Mail) records"""
        try:
            logger.debug(f"Analyzing DKIM records for {domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            # Test common DKIM selectors
            for selector in self.common_dkim_selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    txt_records = resolver.resolve(dkim_domain, 'TXT')
                    
                    for record in txt_records:
                        record_text = str(record).strip('"')
                        
                        # Check if this is a DKIM record
                        if 'v=DKIM1' in record_text or 'k=' in record_text or 'p=' in record_text:
                            result.dkim_valid = True
                            result.dkim_selectors.append(selector)
                            result.dkim_records.append({
                                'selector': selector,
                                'record': record_text
                            })
                            
                            # Analyze DKIM record
                            await self._analyze_dkim_record(record_text, selector, result)
                
                except dns.resolver.NoAnswer:
                    # No DKIM record for this selector
                    pass
                except dns.resolver.NXDOMAIN:
                    # Selector doesn't exist
                    pass
                except Exception as e:
                    logger.debug(f"DKIM check failed for {selector}._domainkey.{domain}: {str(e)}")
            
            if not result.dkim_valid:
                result.security_issues.append("No DKIM records found")
                
        except Exception as e:
            logger.debug(f"DKIM analysis failed for {domain}: {str(e)}")
    
    async def _analyze_dkim_record(self, dkim_record: str, selector: str, result: EmailSecurityResult):
        """Analyze individual DKIM record"""
        try:
            # Check key type
            if 'k=rsa' in dkim_record or 'k=' not in dkim_record:
                # RSA is default and acceptable
                pass
            else:
                result.security_issues.append(f"DKIM selector {selector} uses non-RSA key type")
            
            # Check if public key is present
            if 'p=' not in dkim_record:
                result.security_issues.append(f"DKIM selector {selector} missing public key")
            elif 'p=""' in dkim_record or 'p=' == dkim_record.split('p=')[1].split(';')[0]:
                result.security_issues.append(f"DKIM selector {selector} has empty public key")
            
            # Check for test mode
            if 't=y' in dkim_record:
                result.security_issues.append(f"DKIM selector {selector} is in test mode")
            
        except Exception as e:
            logger.debug(f"DKIM record analysis failed for {selector}: {str(e)}")
    
    async def _analyze_dmarc_record(self, domain: str, result: EmailSecurityResult):
        """Analyze DMARC (Domain-based Message Authentication) record"""
        try:
            logger.debug(f"Analyzing DMARC record for {domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                # Query for DMARC record
                dmarc_domain = f"_dmarc.{domain}"
                txt_records = resolver.resolve(dmarc_domain, 'TXT')
                
                for record in txt_records:
                    record_text = str(record).strip('"')
                    
                    # Check if this is a DMARC record
                    if record_text.startswith('v=DMARC1'):
                        result.dmarc_record = record_text
                        result.dmarc_valid = True
                        
                        # Analyze DMARC policy
                        await self._analyze_dmarc_policy(record_text, result)
                        break
                
                if not result.dmarc_record:
                    result.dmarc_valid = False
                    result.security_issues.append("No DMARC record found")
                    
            except dns.resolver.NoAnswer:
                result.dmarc_valid = False
                result.security_issues.append("No DMARC record found")
            except dns.resolver.NXDOMAIN:
                result.dmarc_valid = False
                result.security_issues.append("No DMARC record found")
            except Exception as e:
                logger.debug(f"DMARC analysis failed for {domain}: {str(e)}")
                result.security_issues.append(f"DMARC analysis error: {str(e)}")
                
        except Exception as e:
            logger.debug(f"DMARC record analysis failed for {domain}: {str(e)}")
    
    async def _analyze_dmarc_policy(self, dmarc_record: str, result: EmailSecurityResult):
        """Analyze DMARC policy details"""
        try:
            # Extract policy
            policy_match = re.search(r'p=([^;]+)', dmarc_record)
            if policy_match:
                policy = policy_match.group(1).lower()
                result.dmarc_policy = policy
                
                if policy == 'none':
                    result.security_issues.append("DMARC policy is set to 'none' (monitor only)")
                elif policy not in self.dmarc_policies:
                    result.security_issues.append(f"Invalid DMARC policy: {policy}")
            else:
                result.security_issues.append("DMARC record missing policy")
            
            # Extract percentage
            pct_match = re.search(r'pct=(\d+)', dmarc_record)
            if pct_match:
                pct = int(pct_match.group(1))
                result.dmarc_pct = pct
                if pct < 100:
                    result.security_issues.append(f"DMARC policy applies to only {pct}% of messages")
            else:
                result.dmarc_pct = 100  # Default is 100%
            
            # Check for reporting
            if 'rua=' in dmarc_record or 'ruf=' in dmarc_record:
                result.dmarc_reporting_enabled = True
            else:
                result.security_issues.append("DMARC reporting not configured")
            
            # Check alignment
            if 'aspf=r' in dmarc_record:
                result.security_issues.append("DMARC SPF alignment is relaxed")
            if 'adkim=r' in dmarc_record:
                result.security_issues.append("DMARC DKIM alignment is relaxed")
            
        except Exception as e:
            logger.debug(f"DMARC policy analysis failed: {str(e)}")
    
    async def _analyze_mx_records(self, domain: str, result: EmailSecurityResult):
        """Analyze MX records and mail servers"""
        try:
            logger.debug(f"Analyzing MX records for {domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                mx_records = resolver.resolve(domain, 'MX')
                
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip('.')
                    result.mx_records.append(f"{mx.preference} {mx_host}")
                
                if not result.mx_records:
                    result.security_issues.append("No MX records found")
                    
            except dns.resolver.NoAnswer:
                result.security_issues.append("No MX records found")
            except dns.resolver.NXDOMAIN:
                result.security_issues.append("Domain does not exist")
            except Exception as e:
                logger.debug(f"MX analysis failed for {domain}: {str(e)}")
                result.security_issues.append(f"MX analysis error: {str(e)}")
                
        except Exception as e:
            logger.debug(f"MX record analysis failed for {domain}: {str(e)}")
    
    async def _test_mail_server_security(self, domain: str, result: EmailSecurityResult):
        """Test mail server security"""
        try:
            logger.debug(f"Testing mail server security for {domain}")
            
            # Test each MX record
            for mx_record in result.mx_records:
                mx_host = mx_record.split()[1] if len(mx_record.split()) > 1 else mx_record
                
                # Test SMTP security
                await self._test_smtp_security(mx_host, result)
                
                # Test for open relay
                await self._test_open_relay(mx_host, result)
            
        except Exception as e:
            logger.debug(f"Mail server security test failed for {domain}: {str(e)}")
    
    async def _test_smtp_security(self, mx_host: str, result: EmailSecurityResult):
        """Test SMTP server security"""
        try:
            # Test different SMTP ports
            secure_ports_found = []
            
            for port in [25, 465, 587]:
                try:
                    # Test SSL/TLS support
                    if port == 465:
                        # SMTPS (implicit SSL)
                        context = ssl.create_default_context()
                        with smtplib.SMTP_SSL(mx_host, port, timeout=10, context=context) as smtp:
                            secure_ports_found.append(port)
                    else:
                        # SMTP with STARTTLS
                        with smtplib.SMTP(mx_host, port, timeout=10) as smtp:
                            # Check if STARTTLS is supported
                            if smtp.has_extn('STARTTLS'):
                                smtp.starttls()
                                secure_ports_found.append(port)
                
                except Exception as e:
                    logger.debug(f"SMTP test failed for {mx_host}:{port}: {str(e)}")
            
            if secure_ports_found:
                result.mail_servers_secure = True
            else:
                result.security_issues.append(f"Mail server {mx_host} does not support secure connections")
                
        except Exception as e:
            logger.debug(f"SMTP security test failed for {mx_host}: {str(e)}")
    
    async def _test_open_relay(self, mx_host: str, result: EmailSecurityResult):
        """Test for open relay vulnerability"""
        try:
            logger.debug(f"Testing open relay for {mx_host}")
            
            # Test SMTP connection
            try:
                with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                    smtp.helo('test.example.com')
                    
                    # Try to send email from external domain to external domain
                    try:
                        smtp.mail('test@external.com')
                        smtp.rcpt('relay-test@external.com')
                        
                        # If we get here without exception, it might be an open relay
                        result.open_relay_detected = True
                        result.security_issues.append(f"Potential open relay detected on {mx_host}")
                        
                    except smtplib.SMTPRecipientsRefused:
                        # Expected behavior - relay should be refused
                        pass
                    except smtplib.SMTPResponseException as e:
                        if '550' in str(e) or '554' in str(e):
                            # Relay properly refused
                            pass
                        else:
                            logger.debug(f"Unexpected SMTP response during relay test: {e}")
            
            except Exception as e:
                logger.debug(f"Open relay test failed for {mx_host}: {str(e)}")
                
        except Exception as e:
            logger.debug(f"Open relay test failed for {mx_host}: {str(e)}")
    
    def _calculate_email_security_score(self, result: EmailSecurityResult):
        """Calculate email security score (0-100)"""
        score = 100.0
        
        # SPF scoring (25 points)
        if not result.spf_valid:
            score -= 25
        else:
            if result.spf_includes_all:
                score -= 15
            if result.spf_policy == 'softfail':
                score -= 5
            if result.spf_too_many_lookups:
                score -= 5
        
        # DKIM scoring (25 points)
        if not result.dkim_valid:
            score -= 25
        else:
            # Bonus for having DKIM
            pass
        
        # DMARC scoring (30 points)
        if not result.dmarc_valid:
            score -= 30
        else:
            if result.dmarc_policy == 'none':
                score -= 15
            elif result.dmarc_policy == 'quarantine':
                score -= 5
            # 'reject' is the best policy
            
            if result.dmarc_pct and result.dmarc_pct < 100:
                score -= 5
            
            if not result.dmarc_reporting_enabled:
                score -= 5
        
        # Mail server security (15 points)
        if not result.mail_servers_secure:
            score -= 10
        
        if result.open_relay_detected:
            score -= 15
        
        # MX records (5 points)
        if not result.mx_records:
            score -= 5
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        result.email_security_score = score
        
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
    
    def _generate_email_recommendations(self, result: EmailSecurityResult):
        """Generate email security recommendations"""
        recommendations = []
        
        # SPF recommendations
        if not result.spf_valid:
            recommendations.append("Implement SPF record to prevent email spoofing")
            recommendations.append("Use 'v=spf1 include:_spf.google.com ~all' as a starting point for Google Workspace")
        else:
            if result.spf_includes_all:
                recommendations.append("Remove '+all' from SPF record - it allows any server to send email")
            if result.spf_policy == 'softfail':
                recommendations.append("Change SPF policy from '~all' to '-all' for stricter enforcement")
            if result.spf_too_many_lookups:
                recommendations.append("Reduce DNS lookups in SPF record to 10 or fewer")
        
        # DKIM recommendations
        if not result.dkim_valid:
            recommendations.append("Implement DKIM signing for email authentication")
            recommendations.append("Configure DKIM records with at least 2048-bit RSA keys")
        
        # DMARC recommendations
        if not result.dmarc_valid:
            recommendations.append("Implement DMARC policy starting with 'p=none' for monitoring")
            recommendations.append("Configure DMARC reporting (rua and ruf) to monitor email authentication")
        else:
            if result.dmarc_policy == 'none':
                recommendations.append("Gradually move DMARC policy from 'none' to 'quarantine' then 'reject'")
            elif result.dmarc_policy == 'quarantine':
                recommendations.append("Consider upgrading DMARC policy to 'reject' for maximum protection")
            
            if result.dmarc_pct and result.dmarc_pct < 100:
                recommendations.append("Increase DMARC percentage to 100% once confident in configuration")
            
            if not result.dmarc_reporting_enabled:
                recommendations.append("Configure DMARC aggregate and forensic reporting")
        
        # Mail server recommendations
        if not result.mail_servers_secure:
            recommendations.append("Enable SSL/TLS encryption on mail servers")
            recommendations.append("Support STARTTLS for secure SMTP connections")
        
        if result.open_relay_detected:
            recommendations.append("Configure mail server to prevent open relay abuse")
            recommendations.append("Restrict relay permissions to authorized users/networks only")
        
        # General recommendations
        if result.email_security_score < 80:
            recommendations.append("Implement comprehensive email security monitoring")
            recommendations.append("Consider using a managed email security service")
            recommendations.append("Regularly test email authentication configuration")
        
        if not result.mx_records:
            recommendations.append("Configure MX records for email delivery")
        
        result.recommendations = recommendations 