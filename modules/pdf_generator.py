"""
PDF Report Generator Module
Generates professional PDF reports from scan data using HTML templates
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import json

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logging.warning("WeasyPrint not available. PDF generation will be disabled.")

from jinja2 import Template, Environment, FileSystemLoader
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Generates PDF reports from scan data using HTML templates"""
    
    def __init__(self, template_dir: str = "templates", output_dir: str = "reports"):
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )
        
        # Template mapping
        self.templates = {
            'threat_analysis': 'cyber_threat_analysis_slide.html'
        }
        
        if not WEASYPRINT_AVAILABLE:
            logger.error("WeasyPrint not available. Install with: pip install weasyprint")
    
    def generate_threat_analysis_pdf(self, scan_data: Dict[str, Any], scan_id: str) -> Optional[str]:
        """
        Generate threat analysis PDF report from scan data
        
        Args:
            scan_data: Complete scan results data
            scan_id: Unique scan identifier
            
        Returns:
            Path to generated PDF file or None if failed
        """
        if not WEASYPRINT_AVAILABLE:
            logger.error("Cannot generate PDF: WeasyPrint not available")
            return None
            
        try:
            # Load and populate template
            populated_html = self._populate_threat_analysis_template(scan_data)
            if not populated_html:
                logger.error("Failed to populate template")
                return None
            
            # Generate PDF filename
            domain = scan_data.get('lead', {}).get('domain', 'unknown')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_analysis_{scan_id}_{domain}_{timestamp}.pdf"
            output_path = self.output_dir / filename
            
            # Generate PDF
            logger.info(f"Generating PDF report: {filename}")
            font_config = FontConfiguration()
            
            html_doc = HTML(string=populated_html, base_url=str(self.template_dir))
            html_doc.write_pdf(str(output_path), font_config=font_config)
            
            logger.info(f"✓ PDF report generated successfully: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return None
    
    def _populate_threat_analysis_template(self, scan_data: Dict[str, Any]) -> Optional[str]:
        """Populate the threat analysis template with scan data"""
        try:
            # Load the template
            template_path = self.template_dir / self.templates['threat_analysis']
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            # Parse with BeautifulSoup for easier manipulation
            soup = BeautifulSoup(template_content, 'html.parser')
            
            # Extract data from scan results
            risk_data = self._extract_risk_data(scan_data)
            vulnerability_data = self._extract_vulnerability_data(scan_data)
            asset_data = self._extract_asset_data(scan_data)
            company_data = self._extract_company_data(scan_data)
            
            # Populate editable fields
            self._update_editable_field(soup, "Noga ISO", company_data['company_name'])
            self._update_editable_field(soup, "52.9", str(risk_data['risk_score']))
            self._update_editable_field(soup, "HIGH RISK", risk_data['risk_category'])
            self._update_editable_field(soup, "July 13, 2025", risk_data['scan_date'])
            self._update_editable_field(soup, "noga-iso.co.il", company_data['domain'])
            self._update_editable_field(soup, "24", str(asset_data['total_assets']))
            
            # Update statistics
            stat_numbers = soup.find_all('div', class_='stat-number editable')
            if len(stat_numbers) >= 4:
                stat_numbers[0].string = str(vulnerability_data['total_vulnerabilities'])
                stat_numbers[1].string = str(asset_data['open_ports'])
                stat_numbers[2].string = asset_data['security_grade']
                stat_numbers[3].string = asset_data['dnssec_status']
            
            # Update vulnerability lists
            self._update_vulnerability_lists(soup, vulnerability_data)
            
            # Update critical findings
            self._update_critical_findings(soup, scan_data)
            
            # Update threat summary
            self._update_threat_summary(soup, risk_data, company_data)
            
            return str(soup)
            
        except Exception as e:
            logger.error(f"Failed to populate template: {e}")
            return None
    
    def _extract_risk_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract risk-related data from scan results"""
        risk_score = scan_data.get('risk_score', {})
        overall_score = risk_score.get('overall_score', 0)
        
        # Determine risk category
        if overall_score >= 80:
            risk_category = "CRITICAL RISK"
        elif overall_score >= 60:
            risk_category = "HIGH RISK"
        elif overall_score >= 40:
            risk_category = "MEDIUM RISK"
        else:
            risk_category = "LOW RISK"
        
        return {
            'risk_score': round(overall_score, 1),
            'risk_category': risk_category,
            'scan_date': datetime.now().strftime("%B %d, %Y"),
            'detailed_scores': risk_score.get('detailed_scores', {})
        }
    
    def _extract_vulnerability_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract vulnerability data from scan results"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Group by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vuln_by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
                vuln_by_severity[severity].append(vuln)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'vulnerabilities_by_severity': vuln_by_severity
        }
    
    def _extract_asset_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract asset and infrastructure data from scan results"""
        assets = scan_data.get('assets', [])
        port_scan = scan_data.get('port_scan_results', [])
        ssl_results = scan_data.get('enhanced_ssl_results', [])
        dns_results = scan_data.get('dns_security_results', [])
        
        # Count open ports
        open_ports = 0
        for port_result in port_scan:
            if port_result.get('open_ports'):
                open_ports += len(port_result['open_ports'])
        
        # Get security grade
        security_grade = 'F'  # Default
        if ssl_results and ssl_results[0].get('security_grade'):
            security_grade = ssl_results[0]['security_grade']
        
        # Check DNSSEC
        dnssec_enabled = False
        if dns_results and dns_results[0].get('dnssec_enabled'):
            dnssec_enabled = dns_results[0]['dnssec_enabled']
        
        return {
            'total_assets': len(assets),
            'open_ports': open_ports,
            'security_grade': security_grade,
            'dnssec_status': '✓' if dnssec_enabled else '✗'
        }
    
    def _extract_company_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract company information from scan data"""
        lead = scan_data.get('lead', {})
        return {
            'company_name': lead.get('company_name', 'Unknown Company'),
            'domain': lead.get('domain', 'unknown.com'),
            'industry': lead.get('industry', 'Unknown')
        }
    
    def _update_editable_field(self, soup: BeautifulSoup, old_text: str, new_text: str):
        """Update editable field in the HTML template"""
        for element in soup.find_all(class_='editable'):
            if element.string and old_text in element.string:
                element.string = element.string.replace(old_text, new_text)
            elif element.text and old_text in element.text:
                element.string = element.text.replace(old_text, new_text)
    
    def _update_vulnerability_lists(self, soup: BeautifulSoup, vuln_data: Dict[str, Any]):
        """Update vulnerability lists in the template"""
        vuln_sections = soup.find_all('div', class_='vulnerability-category')
        
        for section in vuln_sections:
            # Determine section type by class or content
            if 'critical' in section.get('class', []):
                severity = 'CRITICAL'
            elif 'high' in section.get('class', []):
                severity = 'HIGH'
            elif 'medium' in section.get('class', []):
                severity = 'MEDIUM'
            elif 'low' in section.get('class', []):
                severity = 'LOW'
            else:
                continue
            
            # Update count in icon
            icon = section.find('div', class_='vuln-icon')
            if icon:
                icon.string = str(vuln_data['severity_counts'][severity])
            
            # Update vulnerability list
            vuln_list = section.find('ul', class_='vuln-list')
            if vuln_list and vuln_data['vulnerabilities_by_severity'][severity]:
                # Clear existing items
                vuln_list.clear()
                
                # Add new items
                for vuln in vuln_data['vulnerabilities_by_severity'][severity][:5]:  # Limit to 5
                    li = soup.new_tag('li', **{'class': 'editable', 'contenteditable': 'true'})
                    li.string = f"{vuln.get('title', 'Unknown Vulnerability')} - {vuln.get('description', '')}"[:100]
                    vuln_list.append(li)
    
    def _update_critical_findings(self, soup: BeautifulSoup, scan_data: Dict[str, Any]):
        """Update critical findings section with real data"""
        findings = []
        
        # Check email security
        email_results = scan_data.get('email_security_results', [])
        if email_results:
            email_result = email_results[0]
            if not email_result.get('dkim_valid') or email_result.get('dmarc_policy') == 'none':
                findings.append({
                    'title': 'Email Security Weakness',
                    'description': f"DKIM: {'✗' if not email_result.get('dkim_valid') else '✓'}, DMARC policy: {email_result.get('dmarc_policy', 'none')} - vulnerable to email spoofing and phishing attacks"
                })
        
        # Check DNS security
        dns_results = scan_data.get('dns_security_results', [])
        if dns_results and not dns_results[0].get('dnssec_enabled'):
            findings.append({
                'title': 'DNS Security Gap',
                'description': 'DNSSEC not enabled - vulnerable to DNS spoofing, cache poisoning, and traffic redirection attacks'
            })
        
        # Check web security headers
        web_results = scan_data.get('web_security_results', [])
        missing_headers = 0
        if web_results:
            security_headers = web_results[0].get('security_headers', {})
            missing_headers = sum(1 for v in security_headers.values() if not v)
        
        if missing_headers > 0:
            findings.append({
                'title': 'Web Application Exposure',
                'description': f"{missing_headers} missing critical security headers create exposure to XSS, clickjacking, and content injection attacks"
            })
        
        # Update findings in template
        finding_items = soup.find_all('div', class_='finding-item')
        for i, finding_item in enumerate(finding_items[:len(findings)]):
            if i < len(findings):
                title_elem = finding_item.find('div', class_='finding-title')
                desc_elem = finding_item.find('div', class_='finding-desc')
                
                if title_elem:
                    title_elem.string = findings[i]['title']
                if desc_elem:
                    desc_elem.string = findings[i]['description']
    
    def _update_threat_summary(self, soup: BeautifulSoup, risk_data: Dict[str, Any], company_data: Dict[str, Any]):
        """Update the threat summary section"""
        summary_text = f"External scan revealed multiple security vulnerabilities across {company_data['company_name']}'s web infrastructure. " \
                      f"With a risk score of {risk_data['risk_score']}, your domain shows significant exposure to cyber threats including " \
                      f"missing security headers, SSL misconfigurations, and email authentication weaknesses that cybercriminals actively exploit."
        
        # Find and update threat summary paragraph
        threat_summary = soup.find('div', class_='threat-summary')
        if threat_summary:
            paragraphs = threat_summary.find_all('p', class_='editable')
            if paragraphs:
                paragraphs[0].string = summary_text
    
    def get_pdf_path(self, scan_id: str) -> Optional[str]:
        """Get the path to a generated PDF report"""
        # Look for PDF files matching the scan ID
        for pdf_file in self.output_dir.glob(f"threat_analysis_{scan_id}_*.pdf"):
            return str(pdf_file)
        return None
    
    def list_generated_reports(self) -> list:
        """List all generated PDF reports"""
        reports = []
        for pdf_file in self.output_dir.glob("threat_analysis_*.pdf"):
            stat = pdf_file.stat()
            reports.append({
                'filename': pdf_file.name,
                'path': str(pdf_file),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'scan_id': self._extract_scan_id_from_filename(pdf_file.name)
            })
        return sorted(reports, key=lambda x: x['created'], reverse=True)
    
    def _extract_scan_id_from_filename(self, filename: str) -> Optional[str]:
        """Extract scan ID from PDF filename"""
        try:
            # Format: threat_analysis_{scan_id}_{domain}_{timestamp}.pdf
            parts = filename.replace('.pdf', '').split('_')
            if len(parts) >= 3 and parts[0] == 'threat' and parts[1] == 'analysis':
                return parts[2]
        except:
            pass
        return None
    
    def cleanup_old_reports(self, max_age_days: int = 30):
        """Clean up old PDF reports"""
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 60 * 60)
        
        deleted_count = 0
        for pdf_file in self.output_dir.glob("threat_analysis_*.pdf"):
            if pdf_file.stat().st_ctime < cutoff_time:
                try:
                    pdf_file.unlink()
                    deleted_count += 1
                    logger.info(f"Deleted old report: {pdf_file.name}")
                except Exception as e:
                    logger.error(f"Failed to delete {pdf_file.name}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old PDF reports") 