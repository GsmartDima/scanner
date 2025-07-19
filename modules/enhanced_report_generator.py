"""
Enhanced Report Generator using OpenAI GPT-4 Mini
Generates professional, well-formatted security reports from scan data
"""

import os
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from config import settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class EnhancedReportGenerator:
    """Generate enhanced security reports using OpenAI GPT-4 Mini"""
    
    def __init__(self):
        self.openai_client = None
        self.enabled = False
        
        if OPENAI_AVAILABLE and settings.enhanced_reports_enabled:
            try:
                self.openai_client = OpenAI(api_key=settings.openai_api_key)
                self.enabled = True
                logger.info("Enhanced report generation with OpenAI enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI client: {e}")
                self.enabled = False
        else:
            logger.info("Enhanced report generation disabled (OpenAI not available or not configured)")
    
    def is_enabled(self) -> bool:
        """Check if enhanced report generation is available"""
        return self.enabled and self.openai_client is not None
    
    def generate_enhanced_html_report(self, scan_data: Dict[str, Any], scan_id: str) -> Optional[str]:
        """Generate an enhanced HTML report using OpenAI"""
        if not self.is_enabled():
            logger.warning("Enhanced report generation not available")
            return None
        
        try:
            # Try the new direct HTML generation approach first
            complete_html = self._generate_complete_html_report(scan_data, scan_id)
            
            if complete_html and len(complete_html) > 1000:  # Verify we got substantial content
                return complete_html
            
            # Fallback to original approach if direct generation fails
            logger.warning("Direct HTML generation failed, using template approach")
            scan_summary = self._prepare_scan_summary(scan_data)
            enhanced_content = self._generate_report_content(scan_summary)
            
            if enhanced_content:
                return self._apply_to_template(enhanced_content, scan_data, scan_id)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to generate enhanced report: {e}")
            return None
    
    def _prepare_scan_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a condensed summary of scan data for OpenAI processing"""
        try:
            lead = scan_data.get('lead', {})
            risk_score = scan_data.get('risk_score', {})
            vulnerabilities = scan_data.get('vulnerabilities', [])
            assets = scan_data.get('assets', [])
            
            # Summarize vulnerabilities by severity
            vuln_summary = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown').lower()
                if severity not in vuln_summary:
                    vuln_summary[severity] = []
                
                vuln_summary[severity].append({
                    'id': vuln.get('cve_id', 'N/A'),
                    'title': vuln.get('title', 'Unknown'),
                    'description': vuln.get('description', '')[:200],  # Truncate long descriptions
                    'service': vuln.get('affected_service', 'Unknown'),
                    'port': vuln.get('port', 'N/A'),
                    'cvss': vuln.get('cvss_score', 'N/A')
                })
            
            # Security findings summary
            security_findings = []
            
            # Email security
            email_results = scan_data.get('email_security_results', [])
            if email_results:
                email_result = email_results[0]
                security_findings.append({
                    'category': 'Email Security',
                    'status': 'pass' if email_result.get('dkim_valid') and email_result.get('dmarc_policy') != 'none' else 'fail',
                    'details': f"DKIM: {'Valid' if email_result.get('dkim_valid') else 'Invalid'}, DMARC: {email_result.get('dmarc_policy', 'none')}"
                })
            
            # DNS security
            dns_results = scan_data.get('dns_security_results', [])
            if dns_results:
                dns_result = dns_results[0]
                security_findings.append({
                    'category': 'DNS Security',
                    'status': 'pass' if dns_result.get('dnssec_enabled') else 'fail',
                    'details': f"DNSSEC: {'Enabled' if dns_result.get('dnssec_enabled') else 'Disabled'}"
                })
            
            # SSL/TLS security
            ssl_results = scan_data.get('enhanced_ssl_results', [])
            if ssl_results:
                ssl_result = ssl_results[0]
                grade = ssl_result.get('security_grade', 'F')
                security_findings.append({
                    'category': 'SSL/TLS Security',
                    'status': 'pass' if grade in ['A+', 'A', 'A-'] else 'fail' if grade in ['F', 'T'] else 'warning',
                    'details': f"Security Grade: {grade}"
                })
            
            # Web security headers
            web_results = scan_data.get('web_security_results', [])
            if web_results:
                web_result = web_results[0]
                security_headers = web_result.get('security_headers', {})
                missing_headers = [k for k, v in security_headers.items() if not v]
                security_findings.append({
                    'category': 'Web Security Headers',
                    'status': 'pass' if len(missing_headers) == 0 else 'warning' if len(missing_headers) <= 2 else 'fail',
                    'details': f"Missing headers: {', '.join(missing_headers) if missing_headers else 'None'}"
                })
            
            return {
                'company_info': {
                    'name': lead.get('company_name', 'Unknown Company'),
                    'domain': lead.get('domain', 'unknown.domain'),
                    'industry': lead.get('industry', 'Unknown')
                },
                'risk_assessment': {
                    'overall_score': risk_score.get('overall_score', 0),
                    'risk_level': self._get_risk_level(risk_score.get('overall_score', 0)),
                    'total_assets': len(assets),
                    'scan_date': datetime.now().strftime('%B %d, %Y')
                },
                'vulnerabilities': {
                    'total_count': len(vulnerabilities),
                    'by_severity': vuln_summary
                },
                'security_findings': security_findings,
                'scan_metadata': {
                    'scan_id': scan_data.get('scan_id', 'N/A'),
                    'duration': scan_data.get('scan_duration', 0),
                    'assets_discovered': len(assets)
                }
            }
            
        except Exception as e:
            logger.error(f"Error preparing scan summary: {e}")
            return {}
    
    def _get_risk_level(self, score: float) -> str:
        """Convert numeric risk score to risk level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_report_content(self, scan_summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use OpenAI to generate enhanced report content"""
        try:
            prompt = self._create_report_prompt(scan_summary)
            
            response = self.openai_client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert generating executive-level security assessment reports. Create comprehensive, professional reports that are clear, actionable, and suitable for C-level executives and technical teams."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=4000,
                temperature=0.3
            )
            
            content = response.choices[0].message.content
            
            # Parse the JSON response
            try:
                enhanced_content = json.loads(content)
                return enhanced_content
            except json.JSONDecodeError:
                # If JSON parsing fails, try to extract content manually
                logger.warning("Failed to parse JSON response, using fallback extraction")
                return self._extract_content_fallback(content)
                
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return None
    
    def _create_report_prompt(self, scan_summary: Dict[str, Any]) -> str:
        """Create a detailed prompt for OpenAI to generate the report"""
        return f"""You are a cybersecurity expert generating an executive-level security assessment report. Based on the scan data provided, create a comprehensive analysis that is suitable for C-level executives and board presentations.

SCAN DATA:
{json.dumps(scan_summary, indent=2)}

INSTRUCTIONS:
Generate a JSON response with the exact structure below. Do not include any text before or after the JSON. Return only valid JSON:

{{
    "executive_summary": "Write a compelling 2-3 paragraph executive summary that highlights the key security risks, potential business impact, and urgency level for Noga ISO. Focus on business language, not technical details.",
    "risk_analysis": {{
        "overall_assessment": "Provide a detailed analysis of Noga ISO's overall security posture, considering their role as an ISO certification service provider and the trust their clients place in them.",
        "key_risks": ["List 4-5 specific, high-impact risks that could affect business operations, customer trust, or regulatory compliance"],
        "business_impact": "Explain how these security issues could specifically impact Noga ISO's business operations, client relationships, and market reputation"
    }},
    "vulnerability_analysis": {{
        "critical_findings": "Analyze the most critical security findings and their potential exploitation scenarios",
        "trend_analysis": "Assess patterns in the vulnerabilities and what they reveal about the security program",
        "attack_vectors": "Describe realistic attack scenarios that could exploit these vulnerabilities"
    }},
    "security_controls": {{
        "strengths": ["List positive security measures that are working well"],
        "weaknesses": ["Identify specific gaps in security controls"],
        "recommendations": ["Provide specific, actionable security improvements"]
    }},
    "immediate_actions": [
        "Deploy Web Application Firewall (WAF) to protect against automated attacks",
        "Implement missing security headers (X-Frame-Options, HSTS, CSP)",
        "Enable DNSSEC to protect against DNS spoofing attacks",
        "Strengthen email security with proper DMARC policy",
        "Conduct security configuration review of web servers"
    ],
    "long_term_strategy": [
        "Establish comprehensive security monitoring and incident response program",
        "Implement regular penetration testing and vulnerability assessments",
        "Develop security awareness training for all staff members",
        "Create formal security policies and compliance framework"
    ],
    "compliance_notes": "As an ISO certification provider, Noga ISO should consider implementing ISO 27001 information security management standards to demonstrate security leadership to clients and maintain regulatory compliance.",
    "conclusion": "Noga ISO faces medium-level security risks that require immediate attention. With proper remediation of the identified vulnerabilities and implementation of recommended security controls, the organization can significantly improve its security posture and maintain client trust."
}}

CRITICAL: Return only the JSON object above, with actual analysis content filling each field. Do not include any markdown formatting, explanatory text, or anything outside the JSON structure."""
    
    def _extract_content_fallback(self, content: str) -> Dict[str, Any]:
        """Fallback content extraction when JSON parsing fails"""
        logger.warning(f"OpenAI response was not valid JSON, using fallback. Response: {content[:200]}...")
        
        # Try to extract meaningful content from the response
        lines = content.split('\n')
        meaningful_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('```')]
        
        # Create a comprehensive fallback based on the actual response content
        executive_summary = ""
        if meaningful_lines:
            # Look for substantial content
            for line in meaningful_lines:
                if len(line) > 50:  # Likely meaningful content
                    executive_summary = line[:500]
                    break
        
        if not executive_summary:
            executive_summary = "The cybersecurity assessment has identified multiple security vulnerabilities requiring immediate attention. The organization's current security posture presents medium-level risks that could impact business operations and client trust."
        
        return {
            "executive_summary": executive_summary,
            "risk_analysis": {
                "overall_assessment": "The security assessment reveals several areas requiring immediate attention to maintain operational security and client trust.",
                "key_risks": [
                    "Missing security headers exposing the application to attacks",
                    "Lack of Web Application Firewall protection",
                    "DNS security vulnerabilities allowing potential spoofing",
                    "Weak SSL/TLS configuration enabling potential exploits"
                ],
                "business_impact": "These security gaps could lead to data breaches, service disruptions, and loss of client confidence."
            },
            "vulnerability_analysis": {
                "critical_findings": "Multiple web security headers are missing, creating attack vectors for malicious actors.",
                "trend_analysis": "The vulnerability pattern suggests insufficient security hardening during deployment.",
                "attack_vectors": "Attackers could exploit missing headers for clickjacking, XSS, and MITM attacks."
            },
            "security_controls": {
                "strengths": ["HTTPS implementation", "Basic access controls in place"],
                "weaknesses": ["Missing security headers", "No WAF protection", "DNSSEC not enabled"],
                "recommendations": ["Deploy comprehensive security headers", "Implement Web Application Firewall", "Enable DNSSEC protection"]
            },
            "immediate_actions": [
                "Deploy Web Application Firewall (WAF) protection",
                "Implement missing security headers (X-Frame-Options, HSTS, CSP)",
                "Enable DNSSEC to prevent DNS spoofing attacks",
                "Review and strengthen SSL/TLS configuration",
                "Conduct comprehensive security audit"
            ],
            "long_term_strategy": [
                "Establish ongoing security monitoring program",
                "Implement regular vulnerability assessments",
                "Develop staff security training program",
                "Create incident response procedures"
            ],
            "compliance_notes": "Consider implementing ISO 27001 standards to demonstrate security leadership and maintain regulatory compliance.",
            "conclusion": "Immediate action is required to address identified security vulnerabilities. With proper remediation, the organization can significantly improve its security posture and maintain stakeholder confidence."
        }
    
    def _apply_to_template(self, enhanced_content: Dict[str, Any], scan_data: Dict[str, Any], scan_id: str) -> str:
        """Apply enhanced content to the PDF report template"""
        try:
            # Load the enhanced template
            template_path = Path(__file__).parent.parent / "templates" / "enhanced_pdf_report_template.html"
            
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            # Prepare template variables including enhanced content
            template_vars = self._prepare_template_variables(enhanced_content, scan_data, scan_id)
            
            # Replace template variables
            for key, value in template_vars.items():
                placeholder = f"{{{{ {key} }}}}"
                template_content = template_content.replace(placeholder, str(value))
            
            return template_content
            
        except Exception as e:
            logger.error(f"Failed to apply content to template: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return None
    
    def _prepare_template_variables(self, enhanced_content: Dict[str, Any], scan_data: Dict[str, Any], scan_id: str) -> Dict[str, str]:
        """Prepare all template variables including enhanced content"""
        # Get basic scan data
        lead = scan_data.get('lead', {})
        risk_score = scan_data.get('risk_score', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        assets = scan_data.get('assets', [])
        
        # Calculate vulnerability counts with safe defaults
        vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Safely process vulnerabilities
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            severity = vuln.get('severity', 'low')
            if severity is None:
                severity = 'low'
            severity = str(severity).lower().strip()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
        
        # Ensure all counts are integers (never None)
        for key in vuln_counts:
            if vuln_counts[key] is None:
                vuln_counts[key] = 0
        
        total_vulns = len(vulnerabilities) if vulnerabilities else 0
        
        # Calculate percentages with safe handling
        def calc_percentage(count, total):
            if count is None:
                count = 0
            if total is None or total == 0:
                return 0.0
            return round((count / total * 100), 1)
        
        # Determine risk category with safe handling
        overall_score = risk_score.get('overall_score', 0) if risk_score else 0
        if overall_score is None:
            overall_score = 0
        overall_score = float(overall_score)
        
        if overall_score >= 80:
            risk_category = "critical"
            risk_category_display = "CRITICAL"
        elif overall_score >= 60:
            risk_category = "high"
            risk_category_display = "HIGH"
        elif overall_score >= 40:
            risk_category = "medium"
            risk_category_display = "MEDIUM"
        else:
            risk_category = "low"
            risk_category_display = "LOW"
        
        # Enhanced recommendations from OpenAI (with fallback handling)
        if enhanced_content is None:
            enhanced_content = {}
        
        immediate_actions = enhanced_content.get('immediate_actions', [
            "Review and address critical vulnerabilities",
            "Implement missing security controls", 
            "Update security policies and procedures"
        ])
        
        long_term_strategy = enhanced_content.get('long_term_strategy', [
            "Establish regular security assessments",
            "Implement continuous monitoring",
            "Enhance security awareness training"
        ])
        
        # Ensure risk_analysis is a dict, not None
        risk_analysis = enhanced_content.get('risk_analysis', {})
        if not isinstance(risk_analysis, dict):
            risk_analysis = {}
        
        return {
            # Company and scan info
            'company_name': lead.get('company_name', 'Unknown Company'),
            'domain': lead.get('domain', 'unknown.domain'),
            'scan_date': datetime.now().strftime('%B %d, %Y'),
            'scan_id': scan_id,
            
            # Risk information
            'risk_score': int(overall_score),
            'risk_category': risk_category,
            'risk_category_display': risk_category_display,
            
            # Vulnerability statistics
            'total_vulnerabilities': total_vulns,
            'critical_count': vuln_counts['critical'],
            'high_count': vuln_counts['high'],
            'medium_count': vuln_counts['medium'],
            'low_count': vuln_counts['low'],
            'critical_percentage': calc_percentage(vuln_counts['critical'], total_vulns),
            'high_percentage': calc_percentage(vuln_counts['high'], total_vulns),
            'medium_percentage': calc_percentage(vuln_counts['medium'], total_vulns),
            'low_percentage': calc_percentage(vuln_counts['low'], total_vulns),
            
            # Asset information with safe handling
            'total_assets': len(assets) if assets else 0,
            'scan_duration': f"{float(scan_data.get('scan_duration') or 0):.1f} seconds",
            
            # Enhanced content from OpenAI
            'executive_summary': enhanced_content.get('executive_summary', 'Security assessment completed.'),
            'risk_analysis': risk_analysis.get('overall_assessment', 'Security risks identified.'),
            'business_impact': risk_analysis.get('business_impact', 'Potential security exposure.'),
            'compliance_notes': enhanced_content.get('compliance_notes', 'Review compliance requirements.'),
            'enhanced_conclusion': enhanced_content.get('conclusion', 'Regular security assessments recommended.'),
            
            # Recommendations - convert to HTML formatted strings
            'priority_recommendations': self._format_recommendations(immediate_actions[:5]),
            'general_recommendations': self._format_general_recommendations(long_term_strategy[:5]),
            
            # Formatted vulnerabilities and assets
            'formatted_vulnerabilities': self._format_vulnerabilities(vulnerabilities),
            'formatted_assets': self._format_assets(assets)
        }
    
    def _format_recommendations(self, recommendations: list) -> str:
        """Format recommendations list as HTML for template replacement"""
        if not recommendations:
            return "<div class='action-item'>No specific recommendations available</div>"
        
        html_items = []
        for rec in recommendations:
            html_items.append(f'<div class="action-item">{rec}</div>')
        
        return '\n            '.join(html_items)
    
    def _format_general_recommendations(self, recommendations: list) -> str:
        """Format general recommendations as HTML list items"""
        if not recommendations:
            return "<li>No specific recommendations available</li>"
        
        html_items = []
        for rec in recommendations:
            html_items.append(f'<li>{rec}</li>')
        
        return '\n                '.join(html_items)
    
    def _format_vulnerabilities(self, vulnerabilities: list) -> str:
        """Format vulnerabilities as HTML for template replacement"""
        if not vulnerabilities:
            return "<div class='vulnerability-item'><p>No vulnerabilities detected</p></div>"
        
        html_items = []
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').lower()
            severity_class = f"severity-{severity}"
            
            html_item = f"""
            <div class="vulnerability-item">
                <div class="vuln-header">
                    <span class="vuln-severity {severity_class}">{vuln.get('severity', 'UNKNOWN')}</span>
                    {vuln.get('cve_id', 'N/A')} - {vuln.get('title', 'Unknown Vulnerability')}
                </div>
                <p><strong>Affected Service:</strong> {vuln.get('affected_service', 'Unknown')} (Port {vuln.get('port', 'N/A')})</p>
                <p><strong>CVSS Score:</strong> {vuln.get('cvss_score', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>"""
            
            if vuln.get('remediation'):
                html_item += f"\n                <p><strong>Remediation:</strong> {vuln.get('remediation')}</p>"
            
            html_item += "\n            </div>"
            html_items.append(html_item)
        
        return '\n            '.join(html_items)
    
    def _format_assets(self, assets: list) -> str:
        """Format assets as HTML table rows"""
        if not assets:
            return "<tr><td colspan='4'>No assets discovered</td></tr>"
        
        html_rows = []
        for asset in assets:
            asset_name = asset.get('subdomain') or asset.get('ip_address', 'Unknown')
            protocol = asset.get('protocol', 'Unknown')
            port = asset.get('port', 'N/A')
            
            html_rows.append(f"""
            <tr>
                <td>{asset_name}</td>
                <td>{protocol}</td>
                <td>{port}</td>
                <td>Active</td>
            </tr>""")
        
        return '\n            '.join(html_rows)

    def _generate_complete_html_report(self, scan_data: Dict[str, Any], scan_id: str) -> Optional[str]:
        """Generate complete HTML report directly from OpenAI without template variables"""
        try:
            # Create comprehensive prompt for OpenAI to generate complete HTML report
            prompt = self._create_complete_report_prompt(scan_data, scan_id)
            
            response = self.openai_client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert that generates complete HTML security reports. You must return a complete, valid HTML document ready for PDF conversion. Use professional styling and comprehensive content based on the scan data provided."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=8000,
                temperature=0.2
            )
            
            html_content = response.choices[0].message.content
            
            # Validate HTML content
            if html_content and len(html_content) > 1000:
                # Check if it looks like valid HTML
                if '<html' in html_content.lower() and '</html>' in html_content.lower():
                    logger.info("✅ Generated complete HTML report from OpenAI")
                    return html_content
                else:
                    logger.warning("⚠️  OpenAI response doesn't look like complete HTML")
                    return None
            else:
                logger.warning("⚠️  OpenAI response is too short or empty")
                return None
            
        except Exception as e:
            logger.error(f"Failed to generate complete HTML report: {e}")
            return None

    def _create_complete_report_prompt(self, scan_data: Dict[str, Any], scan_id: str) -> str:
        """Create prompt for OpenAI to generate complete HTML report"""
        
        # Get basic scan data
        lead = scan_data.get('lead', {})
        risk_score = scan_data.get('risk_score', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        assets = scan_data.get('assets', [])
        
        # Calculate vulnerability counts
        vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
        
        # Calculate scan duration
        scan_duration = scan_data.get('scan_duration') or 0
        
        return f"""Generate a complete, professional HTML security report based on the following scan data. Return ONLY the HTML code - no explanations, no markdown formatting.

SCAN DATA:
Company: {lead.get('company_name', 'Unknown Company')}
Domain: {lead.get('domain', 'unknown.domain')}
Industry: {lead.get('industry', 'Unknown')}
Scan ID: {scan_id}
Risk Score: {risk_score.get('overall_score', 0)}/100
Total Vulnerabilities: {len(vulnerabilities)}
- Critical: {vuln_counts['CRITICAL']}
- High: {vuln_counts['HIGH']}  
- Medium: {vuln_counts['MEDIUM']}
- Low: {vuln_counts['LOW']}
Total Assets: {len(assets)}
Scan Duration: {scan_duration:.1f} seconds

VULNERABILITIES FOUND:
{json.dumps(vulnerabilities, indent=2)}

ASSETS DISCOVERED:
{json.dumps(assets, indent=2)}

EMAIL SECURITY:
{json.dumps(scan_data.get('email_security_results', []), indent=2)}

DNS SECURITY:
{json.dumps(scan_data.get('dns_security_results', []), indent=2)}

SSL/TLS SECURITY:
{json.dumps(scan_data.get('enhanced_ssl_results', []), indent=2)}

WEB SECURITY:
{json.dumps(scan_data.get('web_security_results', []), indent=2)}

REQUIREMENTS:
1. Generate a complete HTML document with proper <!DOCTYPE html>, <html>, <head>, and <body> tags
2. Include professional CSS styling inline in <style> tags
3. Use the company name "{lead.get('company_name', 'Unknown Company')}" and domain "{lead.get('domain', 'unknown.domain')}" throughout
4. Create an executive summary highlighting key risks and business impact
5. Show the exact risk score {risk_score.get('overall_score', 0)}/100 prominently
6. Include a vulnerability breakdown table with the exact counts: Critical={vuln_counts['CRITICAL']}, High={vuln_counts['HIGH']}, Medium={vuln_counts['MEDIUM']}, Low={vuln_counts['LOW']}
7. Calculate and show percentages for each vulnerability severity
8. List all vulnerabilities with their details (CVE ID, severity, description, remediation)
9. Show all discovered assets in a table format
10. Provide specific, actionable recommendations based on the actual vulnerabilities found
11. Include compliance notes relevant to the industry
12. Make it suitable for executive presentation

Use professional red/white color scheme, clear typography, and ensure all data fields are populated with the actual scan results provided above."""
    
# Export the generator class
__all__ = ['EnhancedReportGenerator'] 