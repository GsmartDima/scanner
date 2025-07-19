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
            # Prepare scan data summary for OpenAI
            scan_summary = self._prepare_scan_summary(scan_data)
            
            # Generate enhanced report content
            enhanced_content = self._generate_report_content(scan_summary)
            
            if enhanced_content:
                # Apply the enhanced content to the template
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
        return f"""
Generate a comprehensive cybersecurity assessment report based on the following scan data. Return the response as a JSON object with the specified structure.

SCAN DATA:
{json.dumps(scan_summary, indent=2)}

Please generate a JSON response with the following structure:

{{
    "executive_summary": "A 2-3 paragraph executive summary highlighting key risks, impact, and urgency",
    "risk_analysis": {{
        "overall_assessment": "Detailed analysis of the overall security posture",
        "key_risks": ["List of 3-5 most critical risks identified"],
        "business_impact": "Explanation of potential business impact"
    }},
    "vulnerability_analysis": {{
        "critical_findings": "Analysis of critical vulnerabilities and their implications",
        "trend_analysis": "Assessment of vulnerability patterns and trends",
        "attack_vectors": "Potential attack vectors based on findings"
    }},
    "security_controls": {{
        "strengths": ["List of positive security controls found"],
        "weaknesses": ["List of security control gaps"],
        "recommendations": ["Specific improvement recommendations"]
    }},
    "immediate_actions": [
        "List of 5-7 immediate actions prioritized by risk and impact"
    ],
    "long_term_strategy": [
        "List of 3-5 long-term security improvements"
    ],
    "compliance_notes": "Any relevant compliance considerations (SOC2, ISO27001, etc.)",
    "conclusion": "Professional conclusion with next steps and contact information"
}}

Requirements:
- Use professional, executive-appropriate language
- Focus on business impact and risk
- Provide specific, actionable recommendations
- Avoid technical jargon when possible
- Emphasize urgency appropriately based on risk level
- Include relevant industry best practices
- Make recommendations specific to the company's findings
"""
    
    def _extract_content_fallback(self, content: str) -> Dict[str, Any]:
        """Fallback content extraction when JSON parsing fails"""
        # Simple fallback - return basic structure
        return {
            "executive_summary": content[:500] + "..." if len(content) > 500 else content,
            "risk_analysis": {
                "overall_assessment": "Enhanced analysis generated",
                "key_risks": ["Security vulnerabilities detected"],
                "business_impact": "Potential security exposure identified"
            },
            "immediate_actions": [
                "Review security findings",
                "Implement recommended controls",
                "Monitor for security incidents"
            ]
        }
    
    def _apply_to_template(self, enhanced_content: Dict[str, Any], scan_data: Dict[str, Any], scan_id: str) -> str:
        """Apply enhanced content to the PDF report template"""
        try:
            # Load the base template
            template_path = Path(__file__).parent.parent / "templates" / "pdf_report_template.html"
            
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
            return None
    
    def _prepare_template_variables(self, enhanced_content: Dict[str, Any], scan_data: Dict[str, Any], scan_id: str) -> Dict[str, str]:
        """Prepare all template variables including enhanced content"""
        # Get basic scan data
        lead = scan_data.get('lead', {})
        risk_score = scan_data.get('risk_score', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        assets = scan_data.get('assets', [])
        
        # Calculate vulnerability counts
        vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
        
        total_vulns = len(vulnerabilities)
        
        # Calculate percentages
        def calc_percentage(count, total):
            return round((count / total * 100) if total > 0 else 0, 1)
        
        # Determine risk category
        overall_score = risk_score.get('overall_score', 0)
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
        
        # Enhanced recommendations from OpenAI
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
            
            # Asset information
            'total_assets': len(assets),
            'scan_duration': f"{scan_data.get('scan_duration', 0):.1f} seconds",
            
            # Enhanced content from OpenAI
            'executive_summary': enhanced_content.get('executive_summary', 'Security assessment completed.'),
            'risk_analysis': enhanced_content.get('risk_analysis', {}).get('overall_assessment', 'Security risks identified.'),
            'business_impact': enhanced_content.get('risk_analysis', {}).get('business_impact', 'Potential security exposure.'),
            'compliance_notes': enhanced_content.get('compliance_notes', 'Review compliance requirements.'),
            'enhanced_conclusion': enhanced_content.get('conclusion', 'Regular security assessments recommended.'),
            
            # Recommendations
            'priority_recommendations': immediate_actions[:5],  # Limit to 5
            'general_recommendations': long_term_strategy[:5]   # Limit to 5
        }

# Export the generator class
__all__ = ['EnhancedReportGenerator'] 