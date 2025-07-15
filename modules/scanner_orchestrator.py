"""
Scanner Orchestrator
Main orchestrator that coordinates all scanning modules and manages the scan workflow
"""
import asyncio
import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

from models import (
    Lead, ScanRequest, ScanResult, Asset, PortScanResult, 
    Vulnerability, RiskScore, PeopleDiscoveryResult,
    EnhancedSSLResult, DNSSecurityResult, EmailSecurityResult,
    WebSecurityResult, CloudSecurityResult, APISecurityResult
)
from config import settings
from modules.asset_discovery import AssetDiscoverer
from modules.port_scanner import PortScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.risk_engine import RiskScoringEngine
from modules.people_discovery import PeopleDiscoverer
from modules.ssl_tls_security import SSLTLSSecurityAnalyzer
from modules.dns_security import DNSSecurityAnalyzer
from modules.email_security import EmailSecurityAnalyzer
from modules.web_security import WebSecurityAnalyzer
from modules.cloud_security import CloudSecurityAnalyzer
from modules.api_security import APISecurityAnalyzer
from modules.pdf_generator import PDFReportGenerator

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Scan phases for progress tracking"""
    INITIALIZING = "initializing"
    ASSET_DISCOVERY = "asset_discovery"
    PORT_SCANNING = "port_scanning"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    ENHANCED_SSL_ASSESSMENT = "enhanced_ssl_assessment"
    DNS_SECURITY_ASSESSMENT = "dns_security_assessment"
    EMAIL_SECURITY_ASSESSMENT = "email_security_assessment"
    WEB_SECURITY_ASSESSMENT = "web_security_assessment"
    CLOUD_SECURITY_ASSESSMENT = "cloud_security_assessment"
    API_SECURITY_ASSESSMENT = "api_security_assessment"
    RISK_SCORING = "risk_scoring"
    PDF_GENERATION = "pdf_generation"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProgress:
    """Track detailed scan progress"""
    def __init__(self, scan_id: str, lead: Lead):
        self.scan_id = scan_id
        self.lead = lead
        self.current_phase = ScanPhase.INITIALIZING
        self.phase_progress = 0  # 0-100 percentage
        self.overall_progress = 0  # 0-100 percentage
        self.phases_completed = 0
        self.total_phases = 11  # Updated for new security phases + PDF generation
        self.current_task = "Initializing scan..."
        self.start_time = datetime.now()
        self.phase_start_time = datetime.now()
        self.findings = {
            'assets': [],
            'open_ports': [],
            'vulnerabilities': [],
            'ssl_security': [],
            'dns_security': [],
            'email_security': [],
            'web_security': [],
            'cloud_security': [],
            'api_security': [],
            'risk_indicators': [],
            'people': []
        }
        self.errors = []
        self.status = "running"
        # Add detailed logs for terminal display
        self.logs = []
        self.max_logs = 1000  # Keep last 1000 log entries
        
    def log(self, message: str, level: str = "info", timestamp: datetime = None):
        """Add a log entry with timestamp for terminal display"""
        if timestamp is None:
            timestamp = datetime.now()
            
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'level': level,
            'message': message,
            'phase': self.current_phase.value
        }
        
        self.logs.append(log_entry)
        
        # Keep only the last max_logs entries
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
            
        # Also log to standard logger based on level
        if level == "error":
            logger.error(f"[{self.scan_id}] {message}")
        elif level == "warning":
            logger.warning(f"[{self.scan_id}] {message}")
        elif level == "debug":
            logger.debug(f"[{self.scan_id}] {message}")
        else:
            logger.info(f"[{self.scan_id}] {message}")
        
    def update_phase(self, phase: ScanPhase, task: str = "", progress: int = 0):
        """Update current phase and progress"""
        if phase != self.current_phase:
            if self.current_phase != ScanPhase.INITIALIZING:
                self.log(f"✓ Completed phase: {self.current_phase.value.replace('_', ' ').title()}", "success")
            
            self.phases_completed += 1
            self.current_phase = phase
            self.phase_start_time = datetime.now()
            self.log(f"▶ Starting phase: {phase.value.replace('_', ' ').title()}", "info")
            
        self.current_task = task
        if task:
            self.log(f"  {task}", "debug")
            
        self.phase_progress = min(100, max(0, progress))
        
        # Calculate overall progress
        phase_weight = 100 / self.total_phases
        completed_phases_progress = self.phases_completed * phase_weight
        current_phase_progress = (self.phase_progress / 100) * phase_weight
        self.overall_progress = min(100, completed_phases_progress + current_phase_progress)
        
    def add_finding(self, category: str, finding: Dict[str, Any]):
        """Add a new finding during the scan"""
        if category in self.findings:
            self.findings[category].append({
                **finding,
                'timestamp': datetime.now().isoformat(),
                'phase': self.current_phase.value
            })
            
            # Log the finding for terminal display
            details = finding.get('details', str(finding))
            if category == 'assets':
                self.log(f"  → Found asset: {details}", "success")
            elif category == 'open_ports':
                self.log(f"  → Open port: {details}", "warning")
            elif category == 'vulnerabilities':
                self.log(f"  → Vulnerability: {details}", "error")
            elif category == 'ssl_security':
                self.log(f"  → SSL/TLS issue: {details}", "warning")
            elif category == 'dns_security':
                self.log(f"  → DNS security: {details}", "warning")
            elif category == 'email_security':
                self.log(f"  → Email security: {details}", "warning")
            elif category == 'web_security':
                self.log(f"  → Web security: {details}", "error")
            elif category == 'cloud_security':
                self.log(f"  → Cloud security: {details}", "error")
            elif category == 'api_security':
                self.log(f"  → API security: {details}", "error")
            elif category == 'risk_indicators':
                self.log(f"  → Risk indicator: {details}", "warning")
            elif category == 'people':
                self.log(f"  → People discovery: {details}", "info")
            
    def add_error(self, error: str, phase: str = None):
        """Add an error during the scan"""
        self.errors.append({
            'error': error,
            'phase': phase or self.current_phase.value,
            'timestamp': datetime.now().isoformat()
        })
        
        # Log error for terminal display
        self.log(f"✗ Error: {error}", "error")
        
    def get_recent_logs(self, count: int = 50) -> List[Dict[str, Any]]:
        """Get the most recent log entries"""
        return self.logs[-count:] if count > 0 else self.logs
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert progress to dictionary for API response"""
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        phase_elapsed = (datetime.now() - self.phase_start_time).total_seconds()
        
        return {
            'scan_id': self.scan_id,
            'lead': {
                'domain': self.lead.domain,
                'company_name': self.lead.company_name
            },
            'current_phase': self.current_phase.value,
            'phase_progress': self.phase_progress,
            'overall_progress': self.overall_progress,
            'current_task': self.current_task,
            'status': self.status,
            'elapsed_time': round(elapsed_time, 1),
            'phase_elapsed_time': round(phase_elapsed, 1),
            'findings_count': {
                'assets': len(self.findings['assets']),
                'open_ports': len(self.findings['open_ports']),
                'vulnerabilities': len(self.findings['vulnerabilities']),
                'ssl_security': len(self.findings['ssl_security']),
                'dns_security': len(self.findings['dns_security']),
                'email_security': len(self.findings['email_security']),
                'web_security': len(self.findings['web_security']),
                'cloud_security': len(self.findings['cloud_security']),
                'api_security': len(self.findings['api_security']),
                'risk_indicators': len(self.findings['risk_indicators']),
                'people': len(self.findings['people'])
            },
            'recent_findings': {
                'assets': self.findings['assets'][-3:],  # Last 3 findings
                'open_ports': self.findings['open_ports'][-3:],
                'vulnerabilities': self.findings['vulnerabilities'][-3:],
                'ssl_security': self.findings['ssl_security'][-3:],
                'dns_security': self.findings['dns_security'][-3:],
                'email_security': self.findings['email_security'][-3:],
                'web_security': self.findings['web_security'][-3:],
                'cloud_security': self.findings['cloud_security'][-3:],
                'api_security': self.findings['api_security'][-3:],
                'risk_indicators': self.findings['risk_indicators'][-3:],
                'people': self.findings['people'][-3:]
            },
            'errors': self.errors,
            'phases_completed': self.phases_completed,
            'total_phases': self.total_phases,
            'logs': self.get_recent_logs(100)  # Last 100 log entries
        }


class ScannerOrchestrator:
    """Main orchestrator for cybersecurity scanning workflow"""
    
    def __init__(self):
        self.asset_discoverer = AssetDiscoverer(
            dns_concurrency=settings.dns_concurrency,
            http_concurrency=settings.http_concurrency,
            http_timeout=settings.asset_discovery_timeout
        )
        self.port_scanner = PortScanner()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.risk_engine = RiskScoringEngine()
        self.people_discoverer = PeopleDiscoverer()
        
        # Enhanced security analyzers
        self.ssl_tls_analyzer = SSLTLSSecurityAnalyzer()
        self.dns_security_analyzer = DNSSecurityAnalyzer()
        self.email_security_analyzer = EmailSecurityAnalyzer()
        self.web_security_analyzer = WebSecurityAnalyzer()
        self.cloud_security_analyzer = CloudSecurityAnalyzer()
        self.api_security_analyzer = APISecurityAnalyzer()
        
        # PDF Report Generator
        self.pdf_generator = PDFReportGenerator()
        
        # Track active scans and their progress
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_progress: Dict[str, ScanProgress] = {}
        self.scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        
        # Store scan results (in production, use database)
        self.scan_results: Dict[str, ScanResult] = {}
    
    async def execute_scan(self, scan_request: ScanRequest) -> List[ScanResult]:
        """Execute a complete scan for multiple leads"""
        logger.info(f"Starting scan execution for {len(scan_request.leads)} leads")
        
        scan_results = []
        
        # Create scan tasks
        tasks = []
        for lead in scan_request.leads:
            task = self._scan_single_lead(lead, scan_request)
            tasks.append(task)
        
        # Execute scans with concurrency control
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Scan failed for {scan_request.leads[i].domain}: {str(result)}")
                # Create failed scan result
                failed_scan = ScanResult(
                    scan_id=str(uuid.uuid4()),
                    lead=scan_request.leads[i],
                    scan_status="failed",
                    error_message=str(result),
                    scan_completed_at=datetime.now()
                )
                scan_results.append(failed_scan)
            else:
                scan_results.append(result)
        
        logger.info(f"Scan execution completed: {len(scan_results)} results")
        return scan_results
    
    async def _scan_single_lead(self, lead: Lead, scan_request: ScanRequest) -> ScanResult:
        """Execute complete scan for a single lead with progress tracking"""
        scan_id = str(uuid.uuid4())
        
        async with self.scan_semaphore:
            logger.info(f"Starting scan for {lead.domain} (ID: {scan_id})")
            
            # Initialize progress tracking
            progress = ScanProgress(scan_id, lead)
            self.scan_progress[scan_id] = progress
            
            # Initialize scan result
            scan_result = ScanResult(
                scan_id=scan_id,
                lead=lead,
                scan_status="running",
                scan_started_at=datetime.now()
            )
            
            # Track active scan
            self.active_scans[scan_id] = scan_result
            
            try:
                progress.log(f"🚀 Starting scan for {lead.domain} ({lead.company_name})", "info")
                progress.log(f"Scan ID: {scan_id}", "debug")
                progress.log(f"Scan type: {scan_request.scan_type}", "debug")
                
                # Phase 1: Asset Discovery
                if scan_request.include_subdomains and scan_request.scan_type in ["full", "quick"]:
                    progress.update_phase(ScanPhase.ASSET_DISCOVERY, "Discovering subdomains and assets...", 0)
                    progress.log(f"🔍 Phase 1: Asset discovery for {lead.domain}", "info")
                    progress.log(f"Max subdomains to discover: {scan_request.max_subdomains}", "debug")
                    
                    assets = await self.asset_discoverer.discover_assets(
                        lead, 
                        max_subdomains=scan_request.max_subdomains
                    )
                    scan_result.assets = assets
                    
                    # Add asset findings to progress
                    for asset in assets:
                        progress.add_finding('assets', {
                            'type': 'web_asset',
                            'value': asset.subdomain or asset.ip_address,
                            'details': f"Discovered web asset: {asset.subdomain} on {asset.protocol}:{asset.port}"
                        })
                    
                    progress.update_phase(ScanPhase.ASSET_DISCOVERY, f"Found {len(assets)} assets", 100)
                    progress.log(f"✓ Discovered {len(assets)} assets for {lead.domain}", "success")
                    await asyncio.sleep(0.5)  # Brief pause for progress visibility
                else:
                    progress.log("Skipping asset discovery (not included in scan type)", "debug")
                    scan_result.assets = []
                
                # Phase 2: Port Scanning
                if scan_request.scan_type in ["full", "quick", "ports_only"]:
                    progress.update_phase(ScanPhase.PORT_SCANNING, "Scanning for open ports...", 0)
                    progress.log(f"🔌 Phase 2: Port scanning for {lead.domain}", "info")
                    
                    if scan_request.port_scan_type == "custom" and scan_request.custom_ports:
                        # Quick port check for custom ports
                        progress.update_phase(ScanPhase.PORT_SCANNING, f"Checking {len(scan_request.custom_ports)} custom ports...", 25)
                        progress.log(f"Checking custom ports: {scan_request.custom_ports}", "debug")
                        port_results = await self.port_scanner.quick_port_check(
                            lead.domain, 
                            scan_request.custom_ports
                        )
                    else:
                        # Full port scan
                        progress.update_phase(ScanPhase.PORT_SCANNING, "Scanning common ports...", 25)
                        progress.log(f"Scanning {scan_request.port_scan_type} ports on {len(scan_result.assets) + 1} targets", "debug")
                        port_results = await self.port_scanner.scan_domain_ports(
                            lead, 
                            scan_result.assets, 
                            scan_request.port_scan_type
                        )
                    
                    scan_result.port_scan_results = port_results
                    
                    # Add port findings to progress
                    for port_result in port_results:
                        if port_result.state == 'open':
                            progress.add_finding('open_ports', {
                                'host': port_result.ip_address,
                                'port': port_result.port,
                                'service': port_result.service,
                                'protocol': port_result.protocol,
                                'details': f"Open port {port_result.port}/{port_result.protocol} ({port_result.service}) on {port_result.ip_address}"
                            })
                    
                    open_ports_count = len([pr for pr in port_results if pr.state == 'open'])
                    progress.update_phase(ScanPhase.PORT_SCANNING, f"Found {open_ports_count} open ports", 100)
                    progress.log(f"✓ Port scan completed: {len(port_results)} hosts scanned, {open_ports_count} open ports found", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping port scanning (not included in scan type)", "debug")
                    scan_result.port_scan_results = []
                
                # Phase 3: Vulnerability Assessment
                if (scan_request.include_vulnerability_scan and 
                    scan_request.scan_type in ["full", "vulnerabilities_only"]):
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, "Assessing vulnerabilities...", 0)
                    progress.log(f"🛡️ Phase 3: Vulnerability assessment for {lead.domain}", "info")
                    
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, "Analyzing discovered services...", 25)
                    vulnerabilities = await self.vulnerability_scanner.assess_vulnerabilities(
                        scan_result.port_scan_results,
                        scan_result.assets,
                        scan_result.web_security_results
                    )
                    scan_result.vulnerabilities = vulnerabilities
                    
                    # Add vulnerability findings to progress
                    for vuln in vulnerabilities:
                        progress.add_finding('vulnerabilities', {
                            'cve_id': vuln.cve_id,
                            'severity': vuln.severity,
                            'service': vuln.affected_service,
                            'port': vuln.port,
                            'description': vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description,
                            'details': f"{vuln.severity} vulnerability {vuln.cve_id} found on {vuln.affected_service or 'unknown service'}"
                        })
                    
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, f"Found {len(vulnerabilities)} vulnerabilities", 100)
                    progress.log(f"✓ Found {len(vulnerabilities)} vulnerabilities for {lead.domain}", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping vulnerability assessment (not included in scan type)", "debug")
                    scan_result.vulnerabilities = []
                
                # Enhanced Security Assessments
                
                # Phase 4: Enhanced SSL/TLS Security Assessment
                if (scan_request.include_enhanced_ssl_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.ENHANCED_SSL_ASSESSMENT, "Analyzing SSL/TLS security...", 0)
                    progress.log(f"🔐 Phase 4: Enhanced SSL/TLS security assessment for {lead.domain}", "info")
                    
                    enhanced_ssl_results = await self.ssl_tls_analyzer.analyze_ssl_security(scan_result.assets)
                    scan_result.enhanced_ssl_results = enhanced_ssl_results
                    
                    # Add SSL findings to progress
                    for ssl_result in enhanced_ssl_results:
                        if ssl_result.security_issues:
                            for issue in ssl_result.security_issues:
                                progress.add_finding('ssl_security', {
                                    'domain': ssl_result.domain,
                                    'grade': ssl_result.security_grade,
                                    'score': ssl_result.ssl_security_score,
                                    'issue': issue,
                                    'details': f"SSL/TLS issue on {ssl_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.ENHANCED_SSL_ASSESSMENT, f"Analyzed {len(enhanced_ssl_results)} SSL/TLS configurations", 100)
                    progress.log(f"✓ SSL/TLS analysis completed: {len(enhanced_ssl_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping enhanced SSL/TLS assessment", "debug")
                    scan_result.enhanced_ssl_results = []
                
                # Phase 5: DNS Security Assessment
                if (scan_request.include_dns_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.DNS_SECURITY_ASSESSMENT, "Analyzing DNS security...", 0)
                    progress.log(f"🌐 Phase 5: DNS security assessment for {lead.domain}", "info")
                    
                    dns_results = await self.dns_security_analyzer.analyze_dns_security([lead])
                    scan_result.dns_security_results = dns_results
                    
                    # Add DNS findings to progress
                    for dns_result in dns_results:
                        if dns_result.security_issues:
                            for issue in dns_result.security_issues:
                                progress.add_finding('dns_security', {
                                    'domain': dns_result.domain,
                                    'score': dns_result.dns_security_score,
                                    'issue': issue,
                                    'details': f"DNS security issue for {dns_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.DNS_SECURITY_ASSESSMENT, f"Analyzed {len(dns_results)} DNS configurations", 100)
                    progress.log(f"✓ DNS security analysis completed: {len(dns_results)} domains analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping DNS security assessment", "debug")
                    scan_result.dns_security_results = []
                
                # Phase 6: Email Security Assessment
                if (scan_request.include_email_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.EMAIL_SECURITY_ASSESSMENT, "Analyzing email security...", 0)
                    progress.log(f"📧 Phase 6: Email security assessment for {lead.domain}", "info")
                    
                    email_results = await self.email_security_analyzer.analyze_email_security([lead])
                    scan_result.email_security_results = email_results
                    
                    # Add email findings to progress
                    for email_result in email_results:
                        if email_result.security_issues:
                            for issue in email_result.security_issues:
                                progress.add_finding('email_security', {
                                    'domain': email_result.domain,
                                    'grade': email_result.security_grade,
                                    'score': email_result.email_security_score,
                                    'issue': issue,
                                    'details': f"Email security issue for {email_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.EMAIL_SECURITY_ASSESSMENT, f"Analyzed {len(email_results)} email configurations", 100)
                    progress.log(f"✓ Email security analysis completed: {len(email_results)} domains analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping email security assessment", "debug")
                    scan_result.email_security_results = []
                
                # Phase 7: Web Security Assessment
                if (scan_request.include_web_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.WEB_SECURITY_ASSESSMENT, "Analyzing web application security...", 0)
                    progress.log(f"🌐 Phase 7: Web security assessment for {lead.domain}", "info")
                    
                    web_results = await self.web_security_analyzer.analyze_web_security(scan_result.assets)
                    scan_result.web_security_results = web_results
                    
                    # Add web security findings to progress
                    for web_result in web_results:
                        if web_result.security_issues:
                            for issue in web_result.security_issues:
                                progress.add_finding('web_security', {
                                    'domain': web_result.domain,
                                    'url': web_result.url,
                                    'grade': web_result.security_grade,
                                    'score': web_result.web_security_score,
                                    'issue': issue,
                                    'details': f"Web security issue on {web_result.url}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.WEB_SECURITY_ASSESSMENT, f"Analyzed {len(web_results)} web applications", 100)
                    progress.log(f"✓ Web security analysis completed: {len(web_results)} applications analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping web security assessment", "debug")
                    scan_result.web_security_results = []
                
                # Phase 8: Cloud Security Assessment
                if (scan_request.include_cloud_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.CLOUD_SECURITY_ASSESSMENT, "Analyzing cloud security...", 0)
                    progress.log(f"☁️ Phase 8: Cloud security assessment for {lead.domain}", "info")
                    
                    cloud_results = await self.cloud_security_analyzer.analyze_cloud_security(scan_result.assets)
                    scan_result.cloud_security_results = cloud_results
                    
                    # Add cloud security findings to progress
                    for cloud_result in cloud_results:
                        if cloud_result.security_issues:
                            for issue in cloud_result.security_issues:
                                progress.add_finding('cloud_security', {
                                    'domain': cloud_result.domain,
                                    'provider': cloud_result.cloud_provider,
                                    'score': cloud_result.cloud_security_score,
                                    'issue': issue,
                                    'details': f"Cloud security issue for {cloud_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.CLOUD_SECURITY_ASSESSMENT, f"Analyzed {len(cloud_results)} cloud configurations", 100)
                    progress.log(f"✓ Cloud security analysis completed: {len(cloud_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping cloud security assessment", "debug")
                    scan_result.cloud_security_results = []
                
                # Phase 9: API Security Assessment
                if (scan_request.include_api_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.API_SECURITY_ASSESSMENT, "Analyzing API security...", 0)
                    progress.log(f"🔌 Phase 9: API security assessment for {lead.domain}", "info")
                    
                    api_results = await self.api_security_analyzer.analyze_api_security(scan_result.assets)
                    scan_result.api_security_results = api_results
                    
                    # Add API security findings to progress
                    for api_result in api_results:
                        if api_result.security_issues:
                            for issue in api_result.security_issues:
                                progress.add_finding('api_security', {
                                    'domain': api_result.domain,
                                    'endpoints': len(api_result.api_endpoints),
                                    'score': api_result.api_security_score,
                                    'issue': issue,
                                    'details': f"API security issue for {api_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.API_SECURITY_ASSESSMENT, f"Analyzed {len(api_results)} API configurations", 100)
                    progress.log(f"✓ API security analysis completed: {len(api_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping API security assessment", "debug")
                    scan_result.api_security_results = []
                
                # Phase 10: Risk Scoring
                progress.update_phase(ScanPhase.RISK_SCORING, "Calculating risk score...", 0)
                progress.log(f"🧮 Phase 4: Risk scoring for {lead.domain}", "info")
                
                # Include people discovery data in risk calculation
                people_data = None
                if scan_request.scan_type == "full":
                    progress.log("🔍 Discovering people and email addresses...", "info")
                    people_data = await self.people_discoverer.discover_people(lead, scan_result.assets)
                    scan_result.people_discovery = PeopleDiscoveryResult(**people_data)
                    
                    # Add people findings to progress
                    for email in people_data['emails']:
                        progress.add_finding('people', {
                            'type': 'email',
                            'value': email,
                            'details': f"Email address discovered: {email}"
                        })
                    
                    for name in people_data['names']:
                        progress.add_finding('people', {
                            'type': 'name',
                            'value': name,
                            'details': f"Employee name discovered: {name}"
                        })
                    
                    # Add breach findings
                    for breach in people_data['breach_info']:
                        progress.add_finding('people', {
                            'type': 'breach_risk',
                            'value': breach['email'],
                            'risk_level': breach['risk_level'],
                            'details': f"Data breach risk detected for {breach['email']} ({breach['risk_level']} risk)"
                        })
                    
                    progress.log(f"✓ People discovery: {len(people_data['emails'])} emails, {len(people_data['names'])} names", "success")
                
                # Calculate comprehensive risk score
                progress.update_phase(ScanPhase.RISK_SCORING, "Analyzing security posture...", 50)
                risk_score = self.risk_engine.calculate_risk_score(
                    lead, 
                    scan_result.assets, 
                    scan_result.port_scan_results, 
                    scan_result.vulnerabilities,
                    scan_result.enhanced_ssl_results,
                    scan_result.dns_security_results,
                    scan_result.email_security_results,
                    scan_result.web_security_results,
                    scan_result.cloud_security_results,
                    scan_result.api_security_results
                )
                scan_result.risk_score = risk_score
                
                # Add risk indicators to progress
                if risk_score.risk_category in ['high', 'critical']:
                    progress.add_finding('risk_indicators', {
                        'type': 'high_risk_detected',
                        'score': risk_score.overall_score,
                        'category': risk_score.risk_category,
                        'details': f"High risk detected: {risk_score.overall_score:.1f}/100 ({risk_score.risk_category.upper()})"
                    })
                
                if risk_score.total_vulnerabilities > 5:
                    progress.add_finding('risk_indicators', {
                        'type': 'multiple_vulnerabilities',
                        'count': risk_score.total_vulnerabilities,
                        'details': f"Multiple vulnerabilities detected: {risk_score.total_vulnerabilities} total"
                    })
                
                if risk_score.total_assets > 10:
                    progress.add_finding('risk_indicators', {
                        'type': 'large_attack_surface',
                        'count': risk_score.total_assets,
                        'details': f"Large attack surface: {risk_score.total_assets} assets discovered"
                    })
                
                progress.update_phase(ScanPhase.RISK_SCORING, "Risk analysis complete", 100)
                
                # Phase 11: PDF Report Generation
                progress.update_phase(ScanPhase.PDF_GENERATION, "Generating PDF report...", 0)
                progress.log(f"📄 Phase 11: Generating PDF report for {lead.domain}", "info")
                
                try:
                    # Prepare scan data for PDF generation
                    pdf_scan_data = scan_result.dict()
                    pdf_path = self.pdf_generator.generate_threat_analysis_pdf(pdf_scan_data, scan_id)
                    
                    if pdf_path:
                        scan_result.pdf_report_path = pdf_path
                        progress.log(f"✓ PDF report generated successfully: {pdf_path}", "success")
                        progress.update_phase(ScanPhase.PDF_GENERATION, "PDF report generated", 100)
                    else:
                        progress.log("⚠️ PDF generation failed - scan data saved without report", "warning")
                        progress.update_phase(ScanPhase.PDF_GENERATION, "PDF generation failed", 100)
                        
                except Exception as pdf_error:
                    progress.log(f"⚠️ PDF generation error: {str(pdf_error)}", "warning")
                    progress.update_phase(ScanPhase.PDF_GENERATION, "PDF generation failed", 100)
                    logger.warning(f"PDF generation failed for {scan_id}: {pdf_error}")
                
                # Complete scan
                progress.update_phase(ScanPhase.COMPLETED, "Scan completed successfully", 100)
                progress.status = "completed"
                scan_result.scan_status = "completed"
                scan_result.scan_completed_at = datetime.now()
                
                # Calculate scan duration
                if scan_result.scan_started_at:
                    duration = (scan_result.scan_completed_at - scan_result.scan_started_at).total_seconds()
                    scan_result.scan_duration = duration
                
                progress.log(f"🎉 Scan completed successfully for {lead.domain}", "success")
                progress.log(f"Risk score: {risk_score.overall_score:.1f}/100 ({risk_score.risk_category.upper()})", "info")
                progress.log(f"Scan duration: {duration:.1f} seconds", "info")
                
            except Exception as e:
                progress.log(f"Scan failed for {lead.domain}: {str(e)}", "error")
                progress.update_phase(ScanPhase.FAILED, f"Scan failed: {str(e)}", 0)
                progress.status = "failed"
                progress.add_error(str(e))
                scan_result.scan_status = "failed"
                scan_result.error_message = str(e)
                scan_result.scan_completed_at = datetime.now()
            
            finally:
                # Keep progress for a while after completion
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
            
            return scan_result
    
    def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get progress for a specific scan"""
        if scan_id in self.scan_progress:
            return self.scan_progress[scan_id].to_dict()
        return None
    
    def get_all_scan_progress(self) -> List[Dict[str, Any]]:
        """Get progress for all active scans"""
        return [progress.to_dict() for progress in self.scan_progress.values()]
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        try:
            # Check if scan is active
            if scan_id in self.active_scans:
                # Mark scan as cancelled in progress
                if scan_id in self.scan_progress:
                    progress = self.scan_progress[scan_id]
                    progress.status = "cancelled"
                    progress.current_task = "Scan cancelled by user"
                    progress.log("❌ Scan cancelled by user", "warning")
                
                # Remove from active scans
                del self.active_scans[scan_id]
                
                logger.info(f"Scan {scan_id} cancelled successfully")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Failed to cancel scan {scan_id}: {str(e)}")
            return False
    
    def cleanup_completed_scans(self, max_age_hours: int = 24):
        """Clean up old completed scan progress data"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        completed_scans = []
        
        for scan_id, progress in self.scan_progress.items():
            if (progress.status in ['completed', 'failed'] and 
                progress.start_time < cutoff_time):
                completed_scans.append(scan_id)
        
        for scan_id in completed_scans:
            del self.scan_progress[scan_id]
            
        if completed_scans:
            logger.info(f"Cleaned up {len(completed_scans)} old scan progress records")
    
    async def quick_scan(self, lead: Lead) -> ScanResult:
        """Execute a quick scan with minimal checks"""
        scan_request = ScanRequest(
            leads=[lead],
            scan_type="quick",
            include_subdomains=False,
            max_subdomains=10,
            port_scan_type="default",
            include_vulnerability_scan=False
        )
        
        results = await self.execute_scan(scan_request)
        return results[0] if results else None
    
    async def full_scan(self, lead: Lead) -> ScanResult:
        """Perform a comprehensive scan on a single lead"""
        scan_request = ScanRequest(
            leads=[lead],
            scan_type="full",
            include_subdomains=True,
            max_subdomains=50,
            port_scan_type="common",
            include_vulnerability_scan=True,
            # Enable all enhanced security assessments
            include_enhanced_ssl_scan=True,
            include_dns_security_scan=True,
            include_email_security_scan=True,
            include_web_security_scan=True,
            include_cloud_security_scan=True,
            include_api_security_scan=True
        )
        return await self._scan_single_lead(lead, scan_request)
    
    async def full_scan_with_id(self, lead: Lead, scan_id: str) -> ScanResult:
        """Perform a comprehensive scan on a single lead with a predefined scan ID"""
        scan_request = ScanRequest(
            leads=[lead],
            scan_type="full",
            include_subdomains=True,
            max_subdomains=50,
            port_scan_type="common",
            include_vulnerability_scan=True,
            # Enable all enhanced security assessments
            include_enhanced_ssl_scan=True,
            include_dns_security_scan=True,
            include_email_security_scan=True,
            include_web_security_scan=True,
            include_cloud_security_scan=True,
            include_api_security_scan=True
        )
        return await self._scan_single_lead_with_id(lead, scan_request, scan_id)

    async def _scan_single_lead_with_id(self, lead: Lead, scan_request: ScanRequest, scan_id: str) -> ScanResult:
        """Execute complete scan for a single lead with predefined scan ID"""
        async with self.scan_semaphore:
            logger.info(f"Starting scan for {lead.domain} (ID: {scan_id})")
            
            # Initialize progress tracking with provided scan ID
            progress = ScanProgress(scan_id, lead)
            self.scan_progress[scan_id] = progress
            
            # Initialize scan result with provided scan ID
            scan_result = ScanResult(
                scan_id=scan_id,
                lead=lead,
                scan_status="running",
                scan_started_at=datetime.now()
            )
            
            # Track active scan
            self.active_scans[scan_id] = scan_result
            
            try:
                # Phase 1: Asset Discovery
                if scan_request.include_subdomains and scan_request.scan_type in ["full", "quick"]:
                    progress.update_phase(ScanPhase.ASSET_DISCOVERY, "Discovering subdomains and assets...", 0)
                    logger.info(f"Phase 1: Asset discovery for {lead.domain}")
                    
                    assets = await self.asset_discoverer.discover_assets(
                        lead, 
                        max_subdomains=scan_request.max_subdomains
                    )
                    scan_result.assets = assets
                    
                    # Add asset findings to progress
                    for asset in assets:
                        progress.add_finding('assets', {
                            'type': 'web_asset',
                            'value': asset.subdomain or asset.ip_address,
                            'details': f"Discovered web asset: {asset.subdomain} on {asset.protocol}:{asset.port}"
                        })
                    
                    progress.update_phase(ScanPhase.ASSET_DISCOVERY, f"Found {len(assets)} assets", 100)
                    logger.info(f"Discovered {len(assets)} assets for {lead.domain}")
                    await asyncio.sleep(0.5)  # Brief pause for progress visibility
                else:
                    scan_result.assets = []
                
                # Phase 2: Port Scanning
                if scan_request.scan_type in ["full", "quick", "ports_only"]:
                    progress.update_phase(ScanPhase.PORT_SCANNING, "Scanning for open ports...", 0)
                    logger.info(f"Phase 2: Port scanning for {lead.domain}")
                    
                    if scan_request.port_scan_type == "custom" and scan_request.custom_ports:
                        # Quick port check for custom ports
                        progress.update_phase(ScanPhase.PORT_SCANNING, f"Checking {len(scan_request.custom_ports)} custom ports...", 25)
                        port_results = await self.port_scanner.quick_port_check(
                            lead.domain, 
                            scan_request.custom_ports
                        )
                    else:
                        # Full port scan
                        progress.update_phase(ScanPhase.PORT_SCANNING, "Scanning common ports...", 25)
                        port_results = await self.port_scanner.scan_domain_ports(
                            lead, 
                            scan_result.assets, 
                            scan_request.port_scan_type
                        )
                    
                    scan_result.port_scan_results = port_results
                    
                    # Add port findings to progress
                    for port_result in port_results:
                        if port_result.state == 'open':
                            progress.add_finding('open_ports', {
                                'host': port_result.ip_address,
                                'port': port_result.port,
                                'service': port_result.service,
                                'protocol': port_result.protocol,
                                'details': f"Open port {port_result.port}/{port_result.protocol} ({port_result.service}) on {port_result.ip_address}"
                            })
                    
                    progress.update_phase(ScanPhase.PORT_SCANNING, f"Found {len([pr for pr in port_results if pr.state == 'open'])} open ports", 100)
                    logger.info(f"Port scan completed: {len(port_results)} results for {lead.domain}")
                    await asyncio.sleep(0.5)
                else:
                    scan_result.port_scan_results = []
                
                # Phase 3: Vulnerability Assessment
                if (scan_request.include_vulnerability_scan and 
                    scan_request.scan_type in ["full", "vulnerabilities_only"]):
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, "Assessing vulnerabilities...", 0)
                    logger.info(f"Phase 3: Vulnerability assessment for {lead.domain}")
                    
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, "Analyzing discovered services...", 25)
                    vulnerabilities = await self.vulnerability_scanner.assess_vulnerabilities(
                        scan_result.port_scan_results,
                        scan_result.assets,
                        scan_result.web_security_results
                    )
                    scan_result.vulnerabilities = vulnerabilities
                    
                    # Add vulnerability findings to progress
                    for vuln in vulnerabilities:
                        progress.add_finding('vulnerabilities', {
                            'cve_id': vuln.cve_id,
                            'severity': vuln.severity,
                            'service': vuln.affected_service,
                            'port': vuln.port,
                            'description': vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description,
                            'details': f"{vuln.severity} vulnerability {vuln.cve_id} found on {vuln.affected_service or 'unknown service'}"
                        })
                    
                    progress.update_phase(ScanPhase.VULNERABILITY_ASSESSMENT, f"Found {len(vulnerabilities)} vulnerabilities", 100)
                    logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {lead.domain}")
                    await asyncio.sleep(0.5)
                else:
                    scan_result.vulnerabilities = []
                
                # Phase 4: Enhanced SSL/TLS Security Assessment
                if (scan_request.include_enhanced_ssl_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.ENHANCED_SSL_ASSESSMENT, "Analyzing SSL/TLS security...", 0)
                    progress.log(f"🔐 Phase 4: Enhanced SSL/TLS security assessment for {lead.domain}", "info")
                    
                    enhanced_ssl_results = await self.ssl_tls_analyzer.analyze_ssl_security(scan_result.assets)
                    scan_result.enhanced_ssl_results = enhanced_ssl_results
                    
                    # Add SSL findings to progress
                    for ssl_result in enhanced_ssl_results:
                        if ssl_result.security_issues:
                            for issue in ssl_result.security_issues:
                                progress.add_finding('ssl_security', {
                                    'domain': ssl_result.domain,
                                    'grade': ssl_result.security_grade,
                                    'score': ssl_result.ssl_security_score,
                                    'issue': issue,
                                    'details': f"SSL/TLS issue on {ssl_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.ENHANCED_SSL_ASSESSMENT, f"Analyzed {len(enhanced_ssl_results)} SSL/TLS configurations", 100)
                    progress.log(f"✓ SSL/TLS analysis completed: {len(enhanced_ssl_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping enhanced SSL/TLS assessment", "debug")
                    scan_result.enhanced_ssl_results = []
                
                # Phase 5: DNS Security Assessment
                if (scan_request.include_dns_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.DNS_SECURITY_ASSESSMENT, "Analyzing DNS security...", 0)
                    progress.log(f"🌐 Phase 5: DNS security assessment for {lead.domain}", "info")
                    
                    dns_results = await self.dns_security_analyzer.analyze_dns_security([lead])
                    scan_result.dns_security_results = dns_results
                    
                    # Add DNS findings to progress
                    for dns_result in dns_results:
                        if dns_result.security_issues:
                            for issue in dns_result.security_issues:
                                progress.add_finding('dns_security', {
                                    'domain': dns_result.domain,
                                    'score': dns_result.dns_security_score,
                                    'issue': issue,
                                    'details': f"DNS security issue for {dns_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.DNS_SECURITY_ASSESSMENT, f"Analyzed {len(dns_results)} DNS configurations", 100)
                    progress.log(f"✓ DNS security analysis completed: {len(dns_results)} domains analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping DNS security assessment", "debug")
                    scan_result.dns_security_results = []
                
                # Phase 6: Email Security Assessment
                if (scan_request.include_email_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.EMAIL_SECURITY_ASSESSMENT, "Analyzing email security...", 0)
                    progress.log(f"📧 Phase 6: Email security assessment for {lead.domain}", "info")
                    
                    email_results = await self.email_security_analyzer.analyze_email_security([lead])
                    scan_result.email_security_results = email_results
                    
                    # Add email findings to progress
                    for email_result in email_results:
                        if email_result.security_issues:
                            for issue in email_result.security_issues:
                                progress.add_finding('email_security', {
                                    'domain': email_result.domain,
                                    'grade': email_result.security_grade,
                                    'score': email_result.email_security_score,
                                    'issue': issue,
                                    'details': f"Email security issue for {email_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.EMAIL_SECURITY_ASSESSMENT, f"Analyzed {len(email_results)} email configurations", 100)
                    progress.log(f"✓ Email security analysis completed: {len(email_results)} domains analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping email security assessment", "debug")
                    scan_result.email_security_results = []
                
                # Phase 7: Web Security Assessment
                if (scan_request.include_web_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.WEB_SECURITY_ASSESSMENT, "Analyzing web application security...", 0)
                    progress.log(f"🌐 Phase 7: Web security assessment for {lead.domain}", "info")
                    
                    web_results = await self.web_security_analyzer.analyze_web_security(scan_result.assets)
                    scan_result.web_security_results = web_results
                    
                    # Add web security findings to progress
                    for web_result in web_results:
                        if web_result.security_issues:
                            for issue in web_result.security_issues:
                                progress.add_finding('web_security', {
                                    'domain': web_result.domain,
                                    'url': web_result.url,
                                    'grade': web_result.security_grade,
                                    'score': web_result.web_security_score,
                                    'issue': issue,
                                    'details': f"Web security issue on {web_result.url}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.WEB_SECURITY_ASSESSMENT, f"Analyzed {len(web_results)} web applications", 100)
                    progress.log(f"✓ Web security analysis completed: {len(web_results)} applications analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping web security assessment", "debug")
                    scan_result.web_security_results = []
                
                # Phase 8: Cloud Security Assessment
                if (scan_request.include_cloud_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.CLOUD_SECURITY_ASSESSMENT, "Analyzing cloud security...", 0)
                    progress.log(f"☁️ Phase 8: Cloud security assessment for {lead.domain}", "info")
                    
                    cloud_results = await self.cloud_security_analyzer.analyze_cloud_security(scan_result.assets)
                    scan_result.cloud_security_results = cloud_results
                    
                    # Add cloud security findings to progress
                    for cloud_result in cloud_results:
                        if cloud_result.security_issues:
                            for issue in cloud_result.security_issues:
                                progress.add_finding('cloud_security', {
                                    'domain': cloud_result.domain,
                                    'provider': cloud_result.cloud_provider,
                                    'score': cloud_result.cloud_security_score,
                                    'issue': issue,
                                    'details': f"Cloud security issue for {cloud_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.CLOUD_SECURITY_ASSESSMENT, f"Analyzed {len(cloud_results)} cloud configurations", 100)
                    progress.log(f"✓ Cloud security analysis completed: {len(cloud_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping cloud security assessment", "debug")
                    scan_result.cloud_security_results = []
                
                # Phase 9: API Security Assessment
                if (scan_request.include_api_security_scan and 
                    scan_request.scan_type in ["full"]):
                    progress.update_phase(ScanPhase.API_SECURITY_ASSESSMENT, "Analyzing API security...", 0)
                    progress.log(f"🔌 Phase 9: API security assessment for {lead.domain}", "info")
                    
                    api_results = await self.api_security_analyzer.analyze_api_security(scan_result.assets)
                    scan_result.api_security_results = api_results
                    
                    # Add API security findings to progress
                    for api_result in api_results:
                        if api_result.security_issues:
                            for issue in api_result.security_issues:
                                progress.add_finding('api_security', {
                                    'domain': api_result.domain,
                                    'endpoints': len(api_result.api_endpoints),
                                    'score': api_result.api_security_score,
                                    'issue': issue,
                                    'details': f"API security issue for {api_result.domain}: {issue}"
                                })
                    
                    progress.update_phase(ScanPhase.API_SECURITY_ASSESSMENT, f"Analyzed {len(api_results)} API configurations", 100)
                    progress.log(f"✓ API security analysis completed: {len(api_results)} configurations analyzed", "success")
                    await asyncio.sleep(0.5)
                else:
                    progress.log("Skipping API security assessment", "debug")
                    scan_result.api_security_results = []
                
                # Phase 10: Risk Scoring
                progress.update_phase(ScanPhase.RISK_SCORING, "Calculating risk score...", 0)
                progress.log(f"🧮 Phase 4: Risk scoring for {lead.domain}", "info")
                
                # Include people discovery data in risk calculation
                people_data = None
                if scan_request.scan_type == "full":
                    progress.log("🔍 Discovering people and email addresses...", "info")
                    people_data = await self.people_discoverer.discover_people(lead, scan_result.assets)
                    scan_result.people_discovery = PeopleDiscoveryResult(**people_data)
                    
                    # Add people findings to progress
                    for email in people_data['emails']:
                        progress.add_finding('people', {
                            'type': 'email',
                            'value': email,
                            'details': f"Email address discovered: {email}"
                        })
                    
                    for name in people_data['names']:
                        progress.add_finding('people', {
                            'type': 'name',
                            'value': name,
                            'details': f"Employee name discovered: {name}"
                        })
                    
                    # Add breach findings
                    for breach in people_data['breach_info']:
                        progress.add_finding('people', {
                            'type': 'breach_risk',
                            'value': breach['email'],
                            'risk_level': breach['risk_level'],
                            'details': f"Data breach risk detected for {breach['email']} ({breach['risk_level']} risk)"
                        })
                    
                    progress.log(f"✓ People discovery: {len(people_data['emails'])} emails, {len(people_data['names'])} names", "success")
                
                # Calculate comprehensive risk score
                progress.update_phase(ScanPhase.RISK_SCORING, "Analyzing security posture...", 50)
                risk_score = self.risk_engine.calculate_risk_score(
                    lead, 
                    scan_result.assets, 
                    scan_result.port_scan_results, 
                    scan_result.vulnerabilities,
                    scan_result.enhanced_ssl_results,
                    scan_result.dns_security_results,
                    scan_result.email_security_results,
                    scan_result.web_security_results,
                    scan_result.cloud_security_results,
                    scan_result.api_security_results
                )
                scan_result.risk_score = risk_score
                
                # Add risk indicators to progress
                if risk_score.risk_category in ['high', 'critical']:
                    progress.add_finding('risk_indicators', {
                        'type': 'high_risk_detected',
                        'score': risk_score.overall_score,
                        'category': risk_score.risk_category,
                        'details': f"High risk detected: {risk_score.overall_score:.1f}/100 ({risk_score.risk_category.upper()})"
                    })
                
                if risk_score.total_vulnerabilities > 5:
                    progress.add_finding('risk_indicators', {
                        'type': 'multiple_vulnerabilities',
                        'count': risk_score.total_vulnerabilities,
                        'details': f"Multiple vulnerabilities detected: {risk_score.total_vulnerabilities} total"
                    })
                
                if risk_score.total_assets > 10:
                    progress.add_finding('risk_indicators', {
                        'type': 'large_attack_surface',
                        'count': risk_score.total_assets,
                        'details': f"Large attack surface: {risk_score.total_assets} assets discovered"
                    })
                
                progress.update_phase(ScanPhase.RISK_SCORING, "Risk analysis complete", 100)
                
                # Phase 11: PDF Report Generation
                progress.update_phase(ScanPhase.PDF_GENERATION, "Generating PDF report...", 0)
                progress.log(f"📄 Phase 11: Generating PDF report for {lead.domain}", "info")
                
                try:
                    # Prepare scan data for PDF generation
                    pdf_scan_data = scan_result.dict()
                    pdf_path = self.pdf_generator.generate_threat_analysis_pdf(pdf_scan_data, scan_id)
                    
                    if pdf_path:
                        scan_result.pdf_report_path = pdf_path
                        progress.log(f"✓ PDF report generated successfully: {pdf_path}", "success")
                        progress.update_phase(ScanPhase.PDF_GENERATION, "PDF report generated", 100)
                    else:
                        progress.log("⚠️ PDF generation failed - scan data saved without report", "warning")
                        progress.update_phase(ScanPhase.PDF_GENERATION, "PDF generation failed", 100)
                        
                except Exception as pdf_error:
                    progress.log(f"⚠️ PDF generation error: {str(pdf_error)}", "warning")
                    progress.update_phase(ScanPhase.PDF_GENERATION, "PDF generation failed", 100)
                    logger.warning(f"PDF generation failed for {scan_id}: {pdf_error}")
                
                # Complete scan
                progress.update_phase(ScanPhase.COMPLETED, "Scan completed successfully", 100)
                progress.status = "completed"
                scan_result.scan_status = "completed"
                scan_result.scan_completed_at = datetime.now()
                
                # Calculate scan duration
                if scan_result.scan_started_at:
                    duration = (scan_result.scan_completed_at - scan_result.scan_started_at).total_seconds()
                    scan_result.scan_duration = duration
                
                logger.info(f"Scan completed for {lead.domain}: Risk score {risk_score.overall_score:.1f} ({risk_score.risk_category})")
                
            except Exception as e:
                logger.error(f"Scan failed for {lead.domain}: {str(e)}")
                progress.update_phase(ScanPhase.FAILED, f"Scan failed: {str(e)}", 0)
                progress.status = "failed"
                progress.add_error(str(e))
                scan_result.scan_status = "failed"
                scan_result.error_message = str(e)
                scan_result.scan_completed_at = datetime.now()
            
            finally:
                # Keep progress for a while after completion
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
            
            return scan_result

    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get information about currently active scans"""
        active_scan_info = []
        
        for scan_id, scan_result in self.active_scans.items():
            scan_info = {
                'scan_id': scan_id,
                'domain': scan_result.lead.domain,
                'company_name': scan_result.lead.company_name,
                'status': scan_result.scan_status,
                'started_at': scan_result.scan_started_at.isoformat() if scan_result.scan_started_at else None
            }
            active_scan_info.append(scan_info)
        
        return active_scan_info
    
    def analyze_scan_results(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Analyze multiple scan results for summary statistics"""
        if not scan_results:
            return {}
        
        analysis = {
            'total_scans': len(scan_results),
            'completed_scans': 0,
            'failed_scans': 0,
            'avg_scan_duration': 0.0,
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'total_assets': 0,
            'total_vulnerabilities': 0,
            'total_open_ports': 0,
            'high_risk_domains': [],
            'common_vulnerabilities': {},
            'common_technologies': {}
        }
        
        total_duration = 0.0
        completed_count = 0
        
        for scan in scan_results:
            # Count scan statuses
            if scan.scan_status == "completed":
                analysis['completed_scans'] += 1
                completed_count += 1
                
                if scan.scan_duration:
                    total_duration += scan.scan_duration
                
                # Accumulate statistics
                analysis['total_assets'] += len(scan.assets)
                analysis['total_vulnerabilities'] += len(scan.vulnerabilities)
                analysis['total_open_ports'] += len([p for p in scan.port_scan_results if p.state == 'open'])
                
                # Risk distribution
                if scan.risk_score:
                    category = scan.risk_score.risk_category
                    if category in analysis['risk_distribution']:
                        analysis['risk_distribution'][category] += 1
                    
                    # Track high-risk domains
                    if scan.risk_score.overall_score >= 75:
                        analysis['high_risk_domains'].append({
                            'domain': scan.lead.domain,
                            'score': scan.risk_score.overall_score,
                            'category': scan.risk_score.risk_category
                        })
                
                # Common vulnerabilities
                for vuln in scan.vulnerabilities:
                    if vuln.cve_id not in analysis['common_vulnerabilities']:
                        analysis['common_vulnerabilities'][vuln.cve_id] = {
                            'count': 0,
                            'severity': vuln.severity,
                            'description': vuln.description
                        }
                    analysis['common_vulnerabilities'][vuln.cve_id]['count'] += 1
                
                # Common technologies
                for asset in scan.assets:
                    for tech in asset.tech_stack:
                        if tech not in analysis['common_technologies']:
                            analysis['common_technologies'][tech] = 0
                        analysis['common_technologies'][tech] += 1
                        
            elif scan.scan_status == "failed":
                analysis['failed_scans'] += 1
        
        # Calculate averages
        if completed_count > 0:
            analysis['avg_scan_duration'] = total_duration / completed_count
        
        # Sort high-risk domains by score
        analysis['high_risk_domains'].sort(key=lambda x: x['score'], reverse=True)
        
        # Convert common vulnerabilities to sorted list
        common_vulns = sorted(
            analysis['common_vulnerabilities'].items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]  # Top 10
        
        analysis['common_vulnerabilities'] = [
            {
                'cve_id': cve_id,
                'count': data['count'],
                'severity': data['severity'],
                'description': data['description']
            }
            for cve_id, data in common_vulns
        ]
        
        # Convert common technologies to sorted list
        common_techs = sorted(
            analysis['common_technologies'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]  # Top 10
        
        analysis['common_technologies'] = [
            {'technology': tech, 'count': count}
            for tech, count in common_techs
        ]
        
        return analysis
    
    def generate_executive_summary(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Generate executive summary for scan results"""
        analysis = self.analyze_scan_results(scan_results)
        
        if not analysis:
            return {}
        
        # Calculate key metrics
        total_scans = analysis['total_scans']
        completed_scans = analysis['completed_scans']
        success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Risk assessment
        risk_dist = analysis['risk_distribution']
        high_risk_count = risk_dist.get('high', 0) + risk_dist.get('critical', 0)
        high_risk_percentage = (high_risk_count / completed_scans * 100) if completed_scans > 0 else 0
        
        # Security findings
        avg_vulns_per_domain = (analysis['total_vulnerabilities'] / completed_scans) if completed_scans > 0 else 0
        avg_open_ports_per_domain = (analysis['total_open_ports'] / completed_scans) if completed_scans > 0 else 0
        
        summary = {
            'scan_overview': {
                'total_domains_scanned': total_scans,
                'successful_scans': completed_scans,
                'success_rate_percentage': round(success_rate, 1),
                'avg_scan_duration_minutes': round(analysis['avg_scan_duration'] / 60, 1) if analysis['avg_scan_duration'] else 0
            },
            'risk_assessment': {
                'high_risk_domains_count': high_risk_count,
                'high_risk_percentage': round(high_risk_percentage, 1),
                'risk_distribution': risk_dist,
                'requires_immediate_attention': len([d for d in analysis['high_risk_domains'] if d['score'] >= 90])
            },
            'security_findings': {
                'total_vulnerabilities': analysis['total_vulnerabilities'],
                'avg_vulnerabilities_per_domain': round(avg_vulns_per_domain, 1),
                'total_exposed_services': analysis['total_open_ports'],
                'avg_open_ports_per_domain': round(avg_open_ports_per_domain, 1)
            },
            'key_concerns': self._identify_key_concerns(analysis),
            'recommendations': self._generate_summary_recommendations(analysis),
            'generated_at': datetime.now()
        }
        
        return summary
    
    def _identify_key_concerns(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify key security concerns from analysis"""
        concerns = []
        
        # High-risk domains
        if analysis['high_risk_domains']:
            concerns.append(f"{len(analysis['high_risk_domains'])} domains require immediate security attention")
        
        # Common vulnerabilities
        if analysis['common_vulnerabilities']:
            # PERFORMANCE OPTIMIZATION: Use dict grouping instead of filtering for better performance
            severity_counts = {}
            for v in analysis['common_vulnerabilities']:
                severity = v['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            critical_count = severity_counts.get('CRITICAL', 0)
            if critical_count > 0:
                concerns.append(f"{critical_count} critical vulnerability types found across multiple domains")
        
        # Widespread issues
        avg_vulns = analysis['total_vulnerabilities'] / max(analysis['completed_scans'], 1)
        if avg_vulns > 5:
            concerns.append("High average vulnerability count suggests systemic security issues")
        
        avg_ports = analysis['total_open_ports'] / max(analysis['completed_scans'], 1)
        if avg_ports > 15:
            concerns.append("Large attack surface due to many exposed services")
        
        return concerns
    
    def _generate_summary_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate high-level recommendations based on analysis"""
        recommendations = []
        
        # High-risk domains
        if analysis['high_risk_domains']:
            recommendations.append("Prioritize security assessment for high-risk domains")
        
        # Common vulnerabilities
        if analysis['common_vulnerabilities']:
            top_vuln = analysis['common_vulnerabilities'][0]
            recommendations.append(f"Address {top_vuln['cve_id']} vulnerability across {top_vuln['count']} domains")
        
        # Risk distribution
        risk_dist = analysis['risk_distribution']
        total_assessed = sum(risk_dist.values())
        
        if total_assessed > 0:
            high_risk_pct = (risk_dist.get('high', 0) + risk_dist.get('critical', 0)) / total_assessed
            if high_risk_pct > 0.3:  # More than 30% high risk
                recommendations.append("Implement organization-wide security improvement program")
            elif high_risk_pct > 0.1:  # More than 10% high risk
                recommendations.append("Enhance security monitoring and incident response capabilities")
        
        # General recommendations
        recommendations.extend([
            "Implement regular vulnerability scanning and patch management",
            "Consider cyber insurance policy adjustments based on risk assessment",
            "Establish security baseline requirements for all domains"
        ])
        
        return recommendations 