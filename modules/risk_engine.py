"""
Risk Scoring Engine
Calculates comprehensive risk scores based on discovered assets, vulnerabilities, and security posture
"""
import logging
from typing import List, Dict, Any
from datetime import datetime

from models import (
    RiskScore, Asset, PortScanResult, Vulnerability, Lead,
    EnhancedSSLResult, DNSSecurityResult, EmailSecurityResult,
    WebSecurityResult, CloudSecurityResult, APISecurityResult
)
from config import settings, RISK_CATEGORIES, HIGH_RISK_PORTS, CVE_SEVERITY_SCORES

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculates risk scores based on multiple security factors"""
    
    def __init__(self):
        # Traditional risk weights (reduced to make room for new assessments)
        self.port_weight = 0.15
        self.vuln_weight = 0.20
        self.ssl_weight = 0.10
        self.service_weight = 0.10
        
        # Enhanced security assessment weights
        self.enhanced_ssl_weight = 0.15
        self.dns_security_weight = 0.10
        self.email_security_weight = 0.05
        self.web_security_weight = 0.10
        self.cloud_security_weight = 0.05
        
        # Maximum scores for normalization
        self.max_port_score = 100
        self.max_vuln_score = 100
        self.max_ssl_score = 100
        self.max_service_score = 100
    
    def calculate_risk_score(self, lead: Lead, assets: List[Asset], 
                           port_results: List[PortScanResult], 
                           vulnerabilities: List[Vulnerability],
                           enhanced_ssl_results: List[EnhancedSSLResult] = None,
                           dns_security_results: List[DNSSecurityResult] = None,
                           email_security_results: List[EmailSecurityResult] = None,
                           web_security_results: List[WebSecurityResult] = None,
                           cloud_security_results: List[CloudSecurityResult] = None,
                           api_security_results: List[APISecurityResult] = None) -> RiskScore:
        """Calculate comprehensive risk score for a domain"""
        logger.info(f"Calculating risk score for {lead.domain}")
        
        # Calculate component scores
        port_score = self._calculate_port_risk_score(port_results)
        vuln_score = self._calculate_vulnerability_risk_score(vulnerabilities)
        ssl_score = self._calculate_ssl_risk_score(assets)
        service_score = self._calculate_service_risk_score(port_results, assets)
        
        # Calculate enhanced security assessment scores
        enhanced_ssl_score = self._calculate_enhanced_ssl_risk_score(enhanced_ssl_results or [])
        dns_security_score = self._calculate_dns_security_risk_score(dns_security_results or [])
        email_security_score = self._calculate_email_security_risk_score(email_security_results or [])
        web_security_score = self._calculate_web_security_risk_score(web_security_results or [])
        cloud_security_score = self._calculate_cloud_security_risk_score(cloud_security_results or [])
        
        # Calculate weighted overall score
        overall_score = (
            port_score * self.port_weight +
            vuln_score * self.vuln_weight +
            ssl_score * self.ssl_weight +
            service_score * self.service_weight +
            enhanced_ssl_score * self.enhanced_ssl_weight +
            dns_security_score * self.dns_security_weight +
            email_security_score * self.email_security_weight +
            web_security_score * self.web_security_weight +
            cloud_security_score * self.cloud_security_weight
        )
        
        # Ensure score is within bounds
        overall_score = max(0, min(100, overall_score))
        
        # Determine risk category
        risk_category = self._determine_risk_category(overall_score)
        
        # Count vulnerabilities by severity
        vuln_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
        
        # Identify high-risk ports
        high_risk_ports = self._identify_high_risk_ports(port_results)
        
        # Create risk score object
        risk_score = RiskScore(
            domain=lead.domain,
            overall_score=overall_score,
            risk_category=risk_category,
            port_risk_score=port_score,
            vulnerability_risk_score=vuln_score,
            ssl_risk_score=ssl_score,
            service_risk_score=service_score,
            high_risk_ports=high_risk_ports,
            critical_vulnerabilities=vuln_counts['critical'],
            high_vulnerabilities=vuln_counts['high'],
            medium_vulnerabilities=vuln_counts['medium'],
            low_vulnerabilities=vuln_counts['low'],
            total_assets=len(assets),
            total_open_ports=len([p for p in port_results if p.state == 'open']),
            total_vulnerabilities=len(vulnerabilities),
            calculated_at=datetime.now()
        )
        
        logger.info(f"Risk score for {lead.domain}: {overall_score:.1f} ({risk_category})")
        return risk_score
    
    def _calculate_port_risk_score(self, port_results: List[PortScanResult]) -> float:
        """Calculate risk score based on open ports"""
        if not port_results:
            return 0.0
        
        open_ports = [p for p in port_results if p.state == 'open']
        if not open_ports:
            return 0.0
        
        risk_score = 0.0
        
        for port_result in open_ports:
            port_risk = 1.0  # Base risk for any open port
            
            # Add extra risk for high-risk ports
            if port_result.port in HIGH_RISK_PORTS:
                port_risk += HIGH_RISK_PORTS[port_result.port]['risk']
            
            # Add risk based on service type
            if port_result.service:
                service_risk = self._get_service_risk_multiplier(port_result.service)
                port_risk *= service_risk
            
            risk_score += port_risk
        
        # Normalize based on number of ports and maximum possible risk
        # Cap at reasonable maximum (20 high-risk ports = 100% risk)
        normalized_score = min(100, (risk_score / 20) * 100)
        
        return normalized_score
    
    def _get_service_risk_multiplier(self, service: str) -> float:
        """Get risk multiplier based on service type"""
        service = service.lower()
        
        high_risk_services = {
            'telnet': 3.0,
            'ftp': 2.5,
            'rlogin': 3.0,
            'rsh': 3.0,
            'snmp': 2.0,
            'tftp': 2.5
        }
        
        medium_risk_services = {
            'ssh': 1.5,
            'rdp': 2.0,
            'vnc': 2.0,
            'mysql': 1.8,
            'postgresql': 1.8,
            'mssql': 1.8,
            'mongodb': 1.8,
            'redis': 1.8
        }
        
        for risky_service, multiplier in high_risk_services.items():
            if risky_service in service:
                return multiplier
        
        for risky_service, multiplier in medium_risk_services.items():
            if risky_service in service:
                return multiplier
        
        return 1.0  # Default multiplier
    
    def _calculate_vulnerability_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        risk_score = 0.0
        
        for vuln in vulnerabilities:
            # Base score from CVSS
            cvss_risk = (vuln.cvss_score / 10.0) * 10  # Scale to 0-10
            
            # Severity multiplier
            severity_multipliers = {
                'CRITICAL': 4.0,
                'HIGH': 3.0,
                'MEDIUM': 2.0,
                'LOW': 1.0
            }
            
            severity_multiplier = severity_multipliers.get(vuln.severity, 1.0)
            vuln_risk = cvss_risk * severity_multiplier
            
            # Extra risk for exploitable vulnerabilities
            if vuln.exploit_available:
                vuln_risk *= 1.5
            
            # Reduce risk if patch is available
            if vuln.patch_available:
                vuln_risk *= 0.8
            
            risk_score += vuln_risk
        
        # Normalize the score (assume 10 critical vulnerabilities = 100% risk)
        normalized_score = min(100, (risk_score / 40) * 100)
        
        return normalized_score
    
    def _calculate_ssl_risk_score(self, assets: List[Asset]) -> float:
        """Calculate risk score based on SSL/TLS configuration"""
        if not assets:
            return 0.0
        
        risk_score = 0.0
        web_assets = [a for a in assets if a.protocol in ['http', 'https']]
        
        if not web_assets:
            return 0.0
        
        for asset in web_assets:
            asset_risk = 0.0
            
            # Risk for unencrypted HTTP - but much lower if it's redirect-only
            if asset.protocol == 'http' and asset.port in [80, 8080]:
                if hasattr(asset, 'is_redirect_only') and asset.is_redirect_only:
                    # HTTP that redirects to HTTPS is much lower risk
                    asset_risk += 5.0  # Reduced from 30.0
                    logger.debug(f"HTTP redirect to HTTPS detected for {asset.subdomain} - low risk")
                else:
                    # HTTP serving actual content is higher risk
                    asset_risk += 30.0
                    logger.debug(f"HTTP serving content detected for {asset.subdomain} - higher risk")
            
            # Check security headers
            headers = {k.lower(): v for k, v in asset.headers.items()}
            
            # Missing HSTS
            if 'strict-transport-security' not in headers and asset.protocol == 'https':
                asset_risk += 10.0
            
            # Missing security headers
            security_headers = [
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection',
                'content-security-policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    asset_risk += 2.0
            
            risk_score += asset_risk
        
        # Normalize based on number of web assets
        if web_assets:
            normalized_score = min(100, risk_score / len(web_assets))
        else:
            normalized_score = 0.0
        
        return normalized_score
    
    def _calculate_service_risk_score(self, port_results: List[PortScanResult], 
                                    assets: List[Asset]) -> float:
        """Calculate risk score based on exposed services and their configuration"""
        if not port_results:
            return 0.0
        
        risk_score = 0.0
        open_ports = [p for p in port_results if p.state == 'open']
        
        # Risk factors
        admin_services = ['ssh', 'rdp', 'vnc', 'telnet']
        database_services = ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis']
        file_services = ['ftp', 'sftp', 'tftp', 'nfs']
        
        admin_count = 0
        database_count = 0
        file_count = 0
        outdated_services = 0
        
        for port_result in open_ports:
            service = port_result.service.lower() if port_result.service else ''
            
            # Count service types
            for admin_svc in admin_services:
                if admin_svc in service:
                    admin_count += 1
                    break
            
            for db_svc in database_services:
                if db_svc in service:
                    database_count += 1
                    break
            
            for file_svc in file_services:
                if file_svc in service:
                    file_count += 1
                    break
            
            # Check for outdated versions (simple heuristic)
            if port_result.version and self._is_likely_outdated(service, port_result.version):
                outdated_services += 1
        
        # Calculate risk based on service exposure
        risk_score += admin_count * 15  # Admin services are high risk
        risk_score += database_count * 20  # Database exposure is very high risk
        risk_score += file_count * 10  # File services moderate risk
        risk_score += outdated_services * 5  # Outdated services
        
        # Risk for large attack surface
        if len(open_ports) > 10:
            risk_score += 10
        elif len(open_ports) > 20:
            risk_score += 20
        
        # Normalize score
        normalized_score = min(100, risk_score)
        
        return normalized_score
    
    def _is_likely_outdated(self, service: str, version: str) -> bool:
        """Simple heuristic to detect potentially outdated services"""
        version = version.lower()
        
        # Look for obviously old versions (this is a simplified check)
        old_patterns = [
            r'1\.[0-9]',  # Version 1.x (often old)
            r'2\.0',      # Version 2.0 (depends on service)
            r'0\.[0-9]'   # Version 0.x (often beta/old)
        ]
        
        import re
        for pattern in old_patterns:
            if re.search(pattern, version):
                return True
        
        return False
    
    def _determine_risk_category(self, score: float) -> str:
        """Determine risk category based on score"""
        for category, bounds in RISK_CATEGORIES.items():
            if bounds['min'] <= score <= bounds['max']:
                return category
        return 'medium'  # Default fallback
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _identify_high_risk_ports(self, port_results: List[PortScanResult]) -> List[int]:
        """Identify high-risk open ports"""
        high_risk_ports = []
        
        for port_result in port_results:
            if port_result.state == 'open' and port_result.port in HIGH_RISK_PORTS:
                high_risk_ports.append(port_result.port)
        
        return sorted(list(set(high_risk_ports)))
    
    def generate_risk_recommendations(self, risk_score: RiskScore, 
                                    vulnerabilities: List[Vulnerability],
                                    port_results: List[PortScanResult]) -> List[str]:
        """Generate security recommendations based on risk assessment"""
        recommendations = []
        
        # High-level recommendations based on overall score
        if risk_score.overall_score >= 75:
            recommendations.append("URGENT: Immediate security review required due to critical risk level")
        elif risk_score.overall_score >= 50:
            recommendations.append("HIGH PRIORITY: Schedule security assessment within 30 days")
        elif risk_score.overall_score >= 25:
            recommendations.append("MEDIUM PRIORITY: Security improvements recommended")
        
        # Port-specific recommendations
        if risk_score.high_risk_ports:
            for port in risk_score.high_risk_ports:
                service_info = HIGH_RISK_PORTS.get(port, {})
                recommendations.append(
                    f"Close or secure port {port} ({service_info.get('service', 'Unknown')}): "
                    f"{service_info.get('description', 'High-risk service')}"
                )
        
        # Vulnerability recommendations
        if risk_score.critical_vulnerabilities > 0:
            recommendations.append(
                f"CRITICAL: Patch {risk_score.critical_vulnerabilities} critical vulnerabilities immediately"
            )
        
        if risk_score.high_vulnerabilities > 0:
            recommendations.append(
                f"HIGH: Address {risk_score.high_vulnerabilities} high-severity vulnerabilities"
            )
        
        # SSL/TLS recommendations
        open_ports = [p for p in port_results if p.state == 'open']
        http_ports = [p for p in open_ports if p.port in [80, 8080] and 'http' in (p.service or '').lower()]
        
        if http_ports:
            recommendations.append("Implement HTTPS encryption for all web services")
        
        # Service exposure recommendations
        admin_ports = [p for p in open_ports if p.port in [22, 3389, 23] and p.state == 'open']
        if admin_ports:
            recommendations.append("Restrict administrative service access to trusted networks only")
        
        database_ports = [p for p in open_ports if p.port in [3306, 5432, 1433, 27017, 6379]]
        if database_ports:
            recommendations.append("Database services should not be directly exposed to the internet")
        
        # General recommendations
        if risk_score.total_open_ports > 15:
            recommendations.append("Reduce attack surface by closing unnecessary ports")
        
        if risk_score.total_vulnerabilities > 5:
            recommendations.append("Implement regular vulnerability scanning and patch management")
        
        return recommendations
    
    def compare_risk_scores(self, current_score: RiskScore, 
                          previous_score: RiskScore) -> Dict[str, Any]:
        """Compare current risk score with previous assessment"""
        comparison = {
            'score_change': current_score.overall_score - previous_score.overall_score,
            'category_change': current_score.risk_category != previous_score.risk_category,
            'vulnerability_change': current_score.total_vulnerabilities - previous_score.total_vulnerabilities,
            'port_change': current_score.total_open_ports - previous_score.total_open_ports,
            'trend': 'stable'
        }
        
        # Determine trend
        if comparison['score_change'] > 5:
            comparison['trend'] = 'worsening'
        elif comparison['score_change'] < -5:
            comparison['trend'] = 'improving'
        
        return comparison
    
    def _calculate_enhanced_ssl_risk_score(self, ssl_results: List[EnhancedSSLResult]) -> float:
        """Calculate risk score from enhanced SSL/TLS assessment"""
        if not ssl_results:
            return 0.0
        
        total_risk = 0.0
        for ssl_result in ssl_results:
            # Invert the security score (higher security score = lower risk)
            risk_score = 100 - ssl_result.ssl_security_score
            total_risk += risk_score
        
        # Average risk across all SSL configurations
        return total_risk / len(ssl_results)
    
    def _calculate_dns_security_risk_score(self, dns_results: List[DNSSecurityResult]) -> float:
        """Calculate risk score from DNS security assessment"""
        if not dns_results:
            return 0.0
        
        total_risk = 0.0
        for dns_result in dns_results:
            # Invert the security score
            risk_score = 100 - dns_result.dns_security_score
            total_risk += risk_score
        
        return total_risk / len(dns_results)
    
    def _calculate_email_security_risk_score(self, email_results: List[EmailSecurityResult]) -> float:
        """Calculate risk score from email security assessment"""
        if not email_results:
            return 0.0
        
        total_risk = 0.0
        for email_result in email_results:
            # Invert the security score
            risk_score = 100 - email_result.email_security_score
            total_risk += risk_score
        
        return total_risk / len(email_results)
    
    def _calculate_web_security_risk_score(self, web_results: List[WebSecurityResult]) -> float:
        """Calculate risk score from web security assessment"""
        if not web_results:
            return 0.0
        
        total_risk = 0.0
        for web_result in web_results:
            # Invert the security score
            risk_score = 100 - web_result.web_security_score
            total_risk += risk_score
        
        return total_risk / len(web_results)
    
    def _calculate_cloud_security_risk_score(self, cloud_results: List[CloudSecurityResult]) -> float:
        """Calculate risk score from cloud security assessment"""
        if not cloud_results:
            return 0.0
        
        total_risk = 0.0
        for cloud_result in cloud_results:
            # Invert the security score
            risk_score = 100 - cloud_result.cloud_security_score
            total_risk += risk_score
        
        return total_risk / len(cloud_results)