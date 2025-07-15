"""
Data models for the Cyber Insurance Scanner
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, validator, Field
import validators
from enum import Enum


class Lead(BaseModel):
    """Lead input model"""
    domain: str = Field(..., description="Domain name (FQDN)")
    company_name: str = Field(..., description="Company name")
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain format"""
        if not validators.domain(v):
            raise ValueError(f"Invalid domain format: {v}")
        return v.lower().strip()
    
    @validator('company_name')
    def validate_company_name(cls, v):
        """Validate company name"""
        if not v or len(v.strip()) < 2:
            raise ValueError("Company name must be at least 2 characters")
        return v.strip()


class Asset(BaseModel):
    """Asset discovery result model"""
    domain: str
    subdomain: str
    ip_address: Optional[str] = None
    protocol: str = "http"
    port: int = 80
    title: Optional[str] = None
    tech_stack: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    # Redirect information for better risk assessment
    is_redirect_only: bool = False
    redirect_target: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.now)


class PortScanResult(BaseModel):
    """Port scan result model"""
    domain: str
    ip_address: str
    port: int
    protocol: str = "tcp"
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    os_info: Optional[str] = None
    scanned_at: datetime = Field(default_factory=datetime.now)


class MitreReference(BaseModel):
    """MITRE ATT&CK framework reference"""
    technique_id: str  # e.g., "T1190"
    technique_name: str  # e.g., "Exploit Public-Facing Application"
    tactic: str  # e.g., "Initial Access"
    sub_technique: Optional[str] = None  # e.g., "T1190.001"
    
class Vulnerability(BaseModel):
    """Vulnerability assessment result model"""
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score: float = Field(ge=0, le=10)
    description: str
    affected_service: Optional[str] = None
    affected_version: Optional[str] = None
    port: Optional[int] = None
    exploit_available: bool = False
    patch_available: bool = False
    discovered_at: datetime = Field(default_factory=datetime.now)
    # MITRE ATT&CK references
    mitre_techniques: List[MitreReference] = Field(default_factory=list)
    # Additional metadata
    remediation_advice: Optional[str] = None
    external_references: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)


class SSLResult(BaseModel):
    """SSL/TLS assessment result model"""
    domain: str
    port: int = 443
    has_ssl: bool = False
    ssl_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_valid: bool = False
    certificate_expired: bool = False
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[datetime] = None
    self_signed: bool = False
    weak_cipher: bool = False
    assessed_at: datetime = Field(default_factory=datetime.now)


class EnhancedSSLResult(BaseModel):
    """Enhanced SSL/TLS security assessment result"""
    domain: str
    port: int = 443
    # Basic SSL info
    has_ssl: bool = False
    ssl_versions_supported: List[str] = Field(default_factory=list)
    cipher_suites: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Certificate analysis
    certificate_valid: bool = False
    certificate_expired: bool = False
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_expiry: Optional[datetime] = None
    certificate_san: List[str] = Field(default_factory=list)
    certificate_chain_valid: bool = False
    certificate_signature_algorithm: Optional[str] = None
    self_signed: bool = False
    wildcard_certificate: bool = False
    
    # Security features
    hsts_enabled: bool = False
    hsts_max_age: Optional[int] = None
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    
    # Protocol security
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False
    supports_tls10: bool = False
    supports_ssl3: bool = False
    supports_ssl2: bool = False
    
    # Cipher analysis
    strong_ciphers: int = 0
    weak_ciphers: int = 0
    deprecated_ciphers: int = 0
    forward_secrecy: bool = False
    
    # Vulnerabilities
    vulnerable_to_heartbleed: bool = False
    vulnerable_to_poodle: bool = False
    vulnerable_to_crime: bool = False
    vulnerable_to_breach: bool = False
    vulnerable_to_beast: bool = False
    
    # Security score (0-100)
    ssl_security_score: float = Field(ge=0, le=100, default=0)
    security_grade: str = "F"  # A+, A, B, C, D, E, F
    
    # Issues and recommendations
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class DNSSecurityResult(BaseModel):
    """DNS security assessment result"""
    domain: str
    
    # DNSSEC validation
    dnssec_enabled: bool = False
    dnssec_valid: bool = False
    dnssec_errors: List[str] = Field(default_factory=list)
    
    # DNS record analysis
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    suspicious_records: List[str] = Field(default_factory=list)
    
    # Zone transfer test
    zone_transfer_allowed: bool = False
    zone_transfer_servers: List[str] = Field(default_factory=list)
    
    # Subdomain security
    subdomain_takeover_risk: List[str] = Field(default_factory=list)
    wildcard_dns: bool = False
    
    # DNS infrastructure
    authoritative_servers: List[str] = Field(default_factory=list)
    dns_providers: List[str] = Field(default_factory=list)
    dns_security_score: float = Field(ge=0, le=100, default=0)
    
    # Security issues
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class EmailSecurityResult(BaseModel):
    """Email security assessment result"""
    domain: str
    
    # SPF (Sender Policy Framework)
    spf_record: Optional[str] = None
    spf_valid: bool = False
    spf_policy: Optional[str] = None
    spf_includes_all: bool = False
    spf_too_many_lookups: bool = False
    
    # DKIM (DomainKeys Identified Mail)
    dkim_records: List[Dict[str, str]] = Field(default_factory=list)
    dkim_valid: bool = False
    dkim_selectors: List[str] = Field(default_factory=list)
    
    # DMARC (Domain-based Message Authentication, Reporting & Conformance)
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_pct: Optional[int] = None
    dmarc_valid: bool = False
    dmarc_reporting_enabled: bool = False
    
    # Mail servers
    mx_records: List[str] = Field(default_factory=list)
    mail_servers_secure: bool = False
    open_relay_detected: bool = False
    
    # Security score
    email_security_score: float = Field(ge=0, le=100, default=0)
    security_grade: str = "F"  # A+, A, B, C, D, E, F
    
    # Issues and recommendations
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class WebSecurityResult(BaseModel):
    """Enhanced web application security assessment result"""
    domain: str
    url: str
    
    # Security headers analysis (enhanced)
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    missing_headers: List[str] = Field(default_factory=list)
    insecure_headers: List[str] = Field(default_factory=list)
    
    # Content Security Policy analysis
    csp_enabled: bool = False
    csp_policies: List[str] = Field(default_factory=list)
    csp_unsafe_inline: bool = False
    csp_unsafe_eval: bool = False
    csp_issues: List[str] = Field(default_factory=list)
    
    # Cross-Site Scripting (XSS) detection
    xss_vulnerable: bool = False
    xss_vectors_tested: int = 0
    xss_payloads_successful: List[str] = Field(default_factory=list)
    
    # SQL Injection detection
    sqli_vulnerable: bool = False
    sqli_vectors_tested: int = 0
    sqli_payloads_successful: List[str] = Field(default_factory=list)
    
    # Directory traversal
    directory_traversal_vulnerable: bool = False
    directory_traversal_paths: List[str] = Field(default_factory=list)
    
    # Information disclosure
    information_disclosure: List[str] = Field(default_factory=list)
    directory_listing_enabled: bool = False
    server_info_disclosed: bool = False
    
    # Authentication and session management
    weak_authentication: bool = False
    session_fixation_vulnerable: bool = False
    insecure_session_management: bool = False
    
    # File upload vulnerabilities
    unrestricted_file_upload: bool = False
    file_upload_issues: List[str] = Field(default_factory=list)
    
    # OWASP Top 10 assessment
    owasp_issues: Dict[str, Any] = Field(default_factory=dict)
    
    # Technology-specific vulnerabilities
    cms_vulnerabilities: List[str] = Field(default_factory=list)
    framework_vulnerabilities: List[str] = Field(default_factory=list)
    
    # Security score
    web_security_score: float = Field(ge=0, le=100, default=0)
    security_grade: str = "F"  # A+, A, B, C, D, E, F
    
    # Issues and recommendations
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # WAF detection results
    security_positives: List[str] = Field(default_factory=list)
    missing_security_features: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class CloudSecurityResult(BaseModel):
    """Cloud security assessment result"""
    domain: str
    
    # Cloud provider detection
    cloud_provider: Optional[str] = None  # AWS, Azure, GCP, etc.
    cloud_services: List[str] = Field(default_factory=list)
    
    # AWS specific
    aws_services: Dict[str, Any] = Field(default_factory=dict)
    s3_buckets_found: List[str] = Field(default_factory=list)
    s3_buckets_public: List[str] = Field(default_factory=list)
    aws_regions: List[str] = Field(default_factory=list)
    
    # Azure specific
    azure_services: Dict[str, Any] = Field(default_factory=dict)
    azure_storage_public: List[str] = Field(default_factory=list)
    
    # GCP specific
    gcp_services: Dict[str, Any] = Field(default_factory=dict)
    gcp_storage_public: List[str] = Field(default_factory=list)
    
    # General cloud misconfigurations
    public_cloud_resources: List[str] = Field(default_factory=list)
    insecure_cloud_configs: List[str] = Field(default_factory=list)
    cloud_metadata_exposed: bool = False
    
    # CDN analysis
    cdn_provider: Optional[str] = None
    cdn_misconfigurations: List[str] = Field(default_factory=list)
    
    # Security score
    cloud_security_score: float = Field(ge=0, le=100, default=0)
    
    # Issues and recommendations
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class APISecurityResult(BaseModel):
    """API security assessment result"""
    domain: str
    api_endpoints: List[str] = Field(default_factory=list)
    
    # API discovery
    rest_endpoints: List[str] = Field(default_factory=list)
    graphql_endpoints: List[str] = Field(default_factory=list)
    soap_endpoints: List[str] = Field(default_factory=list)
    
    # Authentication testing
    authentication_required: bool = True
    authentication_bypass: List[str] = Field(default_factory=list)
    weak_authentication: List[str] = Field(default_factory=list)
    
    # Authorization testing
    authorization_issues: List[str] = Field(default_factory=list)
    privilege_escalation: List[str] = Field(default_factory=list)
    
    # Input validation
    input_validation_issues: List[str] = Field(default_factory=list)
    injection_vulnerabilities: List[str] = Field(default_factory=list)
    
    # Rate limiting
    rate_limiting_enabled: bool = False
    rate_limit_bypass: bool = False
    
    # API versioning
    api_versions: List[str] = Field(default_factory=list)
    deprecated_versions: List[str] = Field(default_factory=list)
    
    # Information disclosure
    api_documentation_exposed: bool = False
    sensitive_data_exposed: List[str] = Field(default_factory=list)
    
    # Security score
    api_security_score: float = Field(ge=0, le=100, default=0)
    
    # Issues and recommendations
    security_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    assessed_at: datetime = Field(default_factory=datetime.now)


class RiskScore(BaseModel):
    """Risk scoring result model"""
    domain: str
    overall_score: float = Field(ge=0, le=100)
    risk_category: str  # low, medium, high, critical
    
    # Component scores
    port_risk_score: float = Field(ge=0, le=100)
    vulnerability_risk_score: float = Field(ge=0, le=100)
    ssl_risk_score: float = Field(ge=0, le=100)
    service_risk_score: float = Field(ge=0, le=100)
    
    # Risk factors
    high_risk_ports: List[int] = Field(default_factory=list)
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Metadata
    total_assets: int = 0
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    calculated_at: datetime = Field(default_factory=datetime.now)


class PeopleDiscoveryResult(BaseModel):
    """People discovery results including emails and breach info"""
    emails: List[str] = Field(default_factory=list)
    names: List[str] = Field(default_factory=list)
    job_titles: List[str] = Field(default_factory=list)
    departments: List[str] = Field(default_factory=list)
    social_profiles: List[Dict[str, str]] = Field(default_factory=list)
    breach_info: List[Dict[str, Any]] = Field(default_factory=list)
    assets_checked: int = 0
    sources: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.now)


class ScanResult(BaseModel):
    """Complete scan result model"""
    scan_id: str
    lead: Lead
    assets: List[Asset] = Field(default_factory=list)
    port_scan_results: List[PortScanResult] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    ssl_results: List[SSLResult] = Field(default_factory=list)
    people_discovery: Optional[PeopleDiscoveryResult] = None
    risk_score: Optional[RiskScore] = None
    
    # Enhanced security assessments
    enhanced_ssl_results: List[EnhancedSSLResult] = Field(default_factory=list)
    dns_security_results: List[DNSSecurityResult] = Field(default_factory=list)
    email_security_results: List[EmailSecurityResult] = Field(default_factory=list)
    web_security_results: List[WebSecurityResult] = Field(default_factory=list)
    cloud_security_results: List[CloudSecurityResult] = Field(default_factory=list)
    api_security_results: List[APISecurityResult] = Field(default_factory=list)
    
    # Scan metadata
    scan_status: str = "pending"  # pending, running, completed, failed
    scan_started_at: datetime = Field(default_factory=datetime.now)
    scan_completed_at: Optional[datetime] = None
    scan_duration: Optional[float] = None  # seconds
    error_message: Optional[str] = None


class ScanRequest(BaseModel):
    """Scan request model"""
    leads: List[Lead]
    scan_type: str = "full"  # full, quick, ports_only, vulnerabilities_only
    include_subdomains: bool = True
    max_subdomains: int = 50
    port_scan_type: str = "default"  # default, common, custom
    custom_ports: Optional[List[int]] = None
    include_ssl_scan: bool = True
    include_vulnerability_scan: bool = True
    
    # Enhanced security assessments
    include_enhanced_ssl_scan: bool = True
    include_dns_security_scan: bool = True
    include_email_security_scan: bool = True
    include_web_security_scan: bool = True
    include_cloud_security_scan: bool = True
    include_api_security_scan: bool = True
    
    @validator('scan_type')
    def validate_scan_type(cls, v):
        """Validate scan type"""
        valid_types = ["full", "quick", "ports_only", "vulnerabilities_only"]
        if v not in valid_types:
            raise ValueError(f"Invalid scan type. Must be one of: {valid_types}")
        return v
    
    @validator('port_scan_type')
    def validate_port_scan_type(cls, v):
        """Validate port scan type"""
        valid_types = ["default", "common", "custom"]
        if v not in valid_types:
            raise ValueError(f"Invalid port scan type. Must be one of: {valid_types}")
        return v


class ScanSummary(BaseModel):
    """Scan summary for dashboard"""
    total_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    pending_scans: int = 0
    
    # Risk distribution
    low_risk_count: int = 0
    medium_risk_count: int = 0
    high_risk_count: int = 0
    critical_risk_count: int = 0
    
    # Top risks
    domains_with_critical_vulns: List[str] = Field(default_factory=list)
    most_common_vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    highest_risk_domains: List[Dict[str, Any]] = Field(default_factory=list)
    
    generated_at: datetime = Field(default_factory=datetime.now)


class APIResponse(BaseModel):
    """Standard API response model"""
    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class FileUploadResponse(BaseModel):
    """File upload response model"""
    filename: str
    file_size: int
    leads_count: int
    valid_leads: int
    invalid_leads: int
    errors: List[str] = Field(default_factory=list)
    scan_id: Optional[str] = None 


class DomainSummary(BaseModel):
    """Comprehensive domain summary showing clean vs vulnerable domains"""
    
    # Overall statistics
    total_domains: int = 0
    clean_domains: int = 0
    vulnerable_domains: int = 0
    
    # Clean domains (0 vulnerabilities)
    clean_domain_list: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Vulnerable domains with breakdown
    vulnerable_domain_list: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Severity distribution across all domains
    total_vulnerabilities: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    
    # Summary statistics
    highest_risk_domain: Optional[Dict[str, Any]] = None
    lowest_risk_domain: Optional[Dict[str, Any]] = None
    average_vulnerabilities_per_domain: float = 0.0
    
    # Generated timestamp
    generated_at: datetime = Field(default_factory=datetime.now) 