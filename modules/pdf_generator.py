"""
PDF Report Generator Module
Generates professional PDF reports from scan data using HTML templates
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
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

try:
    from modules.enhanced_report_generator import EnhancedReportGenerator
    ENHANCED_REPORTS_AVAILABLE = True
except ImportError:
    ENHANCED_REPORTS_AVAILABLE = False

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
            'threat_analysis': 'pdf_report_template.html',
            'enhanced_threat_analysis': 'enhanced_pdf_report_template.html',
            'html_report': 'html_report_template.html'
        }
        
        # Initialize enhanced report generator if available
        self.enhanced_generator = None
        if ENHANCED_REPORTS_AVAILABLE:
            try:
                self.enhanced_generator = EnhancedReportGenerator()
                if self.enhanced_generator.is_enabled():
                    logger.info("Enhanced AI-powered report generation enabled")
                else:
                    logger.info("Enhanced report generator available but not enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize enhanced report generator: {e}")
                self.enhanced_generator = None
        
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
            # Try enhanced AI-powered generation first if available
            if self.enhanced_generator and self.enhanced_generator.is_enabled():
                populated_html = self.enhanced_generator.generate_enhanced_html_report(scan_data, scan_id)
                if populated_html:
                    logger.info("Using AI-enhanced report generation")
                else:
                    logger.warning("AI-enhanced generation failed, falling back to standard template")
                    populated_html = self._populate_threat_analysis_template(scan_data)
            else:
                # Use standard template generation
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
            # Load the template using Jinja2
            template = self.jinja_env.get_template(self.templates['threat_analysis'])
            
            # Prepare template data
            template_data = self._prepare_template_data(scan_data)
            
            # Render the template
            rendered_html = template.render(**template_data)
            
            return rendered_html
            
        except Exception as e:
            logger.error(f"Failed to populate template: {e}")
            return None
    
    def _prepare_template_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for template rendering"""
        try:
            # Extract basic info
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
            
            # Prepare vulnerability data for template
            vulnerability_list = []
            for vuln in vulnerabilities:
                vulnerability_list.append({
                    'cve_id': vuln.get('cve_id', 'N/A'),
                    'title': vuln.get('title', vuln.get('cve_id', 'Vulnerability')),
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'severity_lower': vuln.get('severity', 'unknown').lower(),
                    'affected_service': vuln.get('affected_service', 'Unknown'),
                    'port': vuln.get('port', 'N/A'),
                    'cvss_score': vuln.get('cvss_score', 'N/A'),
                    'description': vuln.get('description', 'No description available'),
                    'remediation': vuln.get('remediation', '')
                })
            
            # Generate recommendations
            priority_recommendations = []
            general_recommendations = []
            
            if vuln_counts['critical'] > 0:
                priority_recommendations.append(f"Address {vuln_counts['critical']} critical vulnerabilities immediately")
            if vuln_counts['high'] > 0:
                priority_recommendations.append(f"Remediate {vuln_counts['high']} high-severity vulnerabilities within 30 days")
            
            general_recommendations.extend([
                "Implement a regular vulnerability scanning schedule",
                "Establish a patch management process",
                "Review and update security policies",
                "Consider implementing a Web Application Firewall (WAF)",
                "Conduct security awareness training for staff"
            ])
            
            # Determine risk category display
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
            
            template_data = {
                # Company and scan info
                'company_name': lead.get('company_name', 'Unknown Company'),
                'domain': lead.get('domain', 'unknown.domain'),
                'scan_date': datetime.now().strftime('%B %d, %Y'),
                'scan_id': scan_data.get('scan_id', 'N/A'),
                
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
                
                # Detailed data
                'vulnerabilities': vulnerability_list,
                'assets': assets,
                'priority_recommendations': priority_recommendations,
                'general_recommendations': general_recommendations
            }
            
            return template_data
            
        except Exception as e:
            logger.error(f"Error preparing template data: {e}")
            return {}
    
    def generate_html_report(self, scan_data: Dict[str, Any], scan_id: str) -> Optional[str]:
        """Generate HTML report from scan data"""
        try:
            # Load and populate template
            populated_html = self._populate_html_template(scan_data)
            if not populated_html:
                logger.error("Failed to populate HTML template")
                return None
            
            # Generate HTML filename
            domain = scan_data.get('lead', {}).get('domain', 'unknown')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{scan_id}_{domain}_{timestamp}.html"
            output_path = self.output_dir / filename
            
            # Save HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(populated_html)
            
            logger.info(f"✓ HTML report generated successfully: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return None
    
    def _populate_html_template(self, scan_data: Dict[str, Any]) -> Optional[str]:
        """Populate the HTML template with scan data"""
        try:
            # Check if HTML template exists
            if 'html_report' not in self.templates:
                # Use the PDF template for HTML as well
                template = self.jinja_env.get_template(self.templates['threat_analysis'])
            else:
                template = self.jinja_env.get_template(self.templates['html_report'])
            
            # Prepare template data
            template_data = self._prepare_template_data(scan_data)
            
            # Render the template
            rendered_html = template.render(**template_data)
            
            return rendered_html
            
        except Exception as e:
            logger.error(f"Failed to populate HTML template: {e}")
            return None
    
    def list_generated_reports(self) -> List[Dict[str, Any]]:
        """List all generated PDF and HTML reports"""
        try:
            reports = []
            
            # Check output directory for reports
            if self.output_dir.exists():
                for file_path in self.output_dir.glob("*"):
                    if file_path.is_file() and file_path.suffix in ['.pdf', '.html']:
                        # Extract info from filename
                        filename = file_path.name
                        parts = filename.split('_')
                        
                        if len(parts) >= 3:
                            report_type = parts[0]  # threat_analysis or report
                            scan_id = parts[1] if len(parts) > 1 else 'unknown'
                            domain = parts[2].split('.')[0] if len(parts) > 2 else 'unknown'
                        else:
                            report_type = 'unknown'
                            scan_id = 'unknown'
                            domain = 'unknown'
                        
                        reports.append({
                            'filename': filename,
                            'file_path': str(file_path),
                            'report_type': report_type,
                            'scan_id': scan_id,
                            'domain': domain,
                            'file_type': file_path.suffix[1:],  # Remove the dot
                            'generated_at': datetime.fromtimestamp(file_path.stat().st_mtime),
                            'file_size': file_path.stat().st_size
                        })
            
            # Sort by creation time (newest first)
            reports.sort(key=lambda x: x['generated_at'], reverse=True)
            
            return reports
            
        except Exception as e:
            logger.error(f"Error listing reports: {e}")
            return []
    
    def get_pdf_path(self, scan_id: str) -> Optional[str]:
        """Get the path to a generated PDF report"""
        # Look for PDF files matching the scan ID
        for pdf_file in self.output_dir.glob(f"threat_analysis_{scan_id}_*.pdf"):
            return str(pdf_file)
        return None
    
    def get_html_path(self, scan_id: str) -> Optional[str]:
        """Get the path to a generated HTML report"""
        # Look for HTML files matching the scan ID
        for html_file in self.output_dir.glob(f"report_{scan_id}_*.html"):
            return str(html_file)
        return None
    
    def cleanup_old_reports(self, max_age_days: int = 30):
        """Clean up old PDF and HTML reports"""
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 60 * 60)
        
        deleted_count = 0
        for report_file in self.output_dir.glob("*"):
            if (report_file.is_file() and 
                report_file.suffix in ['.pdf', '.html'] and
                report_file.stat().st_ctime < cutoff_time):
                try:
                    report_file.unlink()
                    deleted_count += 1
                    logger.info(f"Deleted old report: {report_file.name}")
                except Exception as e:
                    logger.error(f"Failed to delete {report_file.name}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old reports") 