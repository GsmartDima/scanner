"""
Security Utilities Module
Provides security functions for SSRF protection, URL validation, and input sanitization
"""
import ipaddress
import socket
import logging
from typing import Set, Union, Optional, List, Dict, Any
from urllib.parse import urlparse
import re
import html
import bleach
from markupsafe import Markup, escape

logger = logging.getLogger(__name__)


class SSRFProtection:
    """Server-Side Request Forgery (SSRF) protection utilities"""
    
    # Private/Internal IP ranges that should be blocked
    PRIVATE_IP_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16'),
        ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
        ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
        ipaddress.IPv4Network('224.0.0.0/4'),  # Multicast
        ipaddress.IPv4Network('240.0.0.0/4'),  # Reserved
        ipaddress.IPv6Network('::1/128'),  # IPv6 loopback
        ipaddress.IPv6Network('fe80::/10'),  # IPv6 link-local
        ipaddress.IPv6Network('fc00::/7'),  # IPv6 unique local
    ]
    
    # Allowed URL schemes
    ALLOWED_SCHEMES = {'http', 'https'}
    
    # Blocked ports (common internal services)
    BLOCKED_PORTS = {
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        110,   # POP3
        111,   # NFS
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5984,  # CouchDB
        6379,  # Redis
        8080,  # Common HTTP alternate
        9200,  # Elasticsearch
        11211, # Memcached
        27017, # MongoDB
    }
    
    @classmethod
    def is_private_ip(cls, ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """Check if IP address is in private/internal range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against private ranges
            for private_range in cls.PRIVATE_IP_RANGES:
                if ip_obj in private_range:
                    return True
            
            return False
            
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip}")
            return True  # Block invalid IPs
    
    @classmethod
    def resolve_hostname(cls, hostname: str) -> Set[str]:
        """Resolve hostname to IP addresses"""
        try:
            # Get all IP addresses for the hostname
            addr_info = socket.getaddrinfo(hostname, None)
            ips = set()
            
            for info in addr_info:
                ip = info[4][0]
                # Remove IPv6 scope ID if present
                if '%' in ip:
                    ip = ip.split('%')[0]
                ips.add(ip)
            
            return ips
            
        except socket.gaierror as e:
            logger.warning(f"Failed to resolve hostname {hostname}: {e}")
            raise ValueError(f"Cannot resolve hostname: {hostname}")
    
    @classmethod
    def validate_url(cls, url: str, allow_private_ips: bool = False) -> bool:
        """
        Validate URL for SSRF protection
        
        Args:
            url: URL to validate
            allow_private_ips: Whether to allow private IP addresses
            
        Returns:
            bool: True if URL is safe, False otherwise
            
        Raises:
            ValueError: If URL is invalid or blocked
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
                raise ValueError(f"Blocked URL scheme: {parsed.scheme}")
            
            # Check hostname
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("Invalid hostname in URL")
            
            # Block localhost variations
            localhost_patterns = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if hostname.lower() in localhost_patterns:
                raise ValueError("Localhost access blocked")
            
            # Check port
            port = parsed.port
            if port and port in cls.BLOCKED_PORTS:
                raise ValueError(f"Blocked port: {port}")
            
            # Resolve hostname and check IP addresses
            try:
                resolved_ips = cls.resolve_hostname(hostname)
                
                for ip in resolved_ips:
                    if not allow_private_ips and cls.is_private_ip(ip):
                        raise ValueError(f"Private IP address blocked: {ip}")
                
                logger.info(f"URL validation passed: {url} -> {resolved_ips}")
                return True
                
            except ValueError as e:
                logger.warning(f"URL validation failed for {url}: {e}")
                raise
            
        except Exception as e:
            logger.error(f"URL validation error for {url}: {e}")
            raise ValueError(f"Invalid URL: {e}")
    
    @classmethod
    def sanitize_url_for_request(cls, url: str) -> str:
        """
        Sanitize URL for making external requests
        
        Args:
            url: URL to sanitize
            
        Returns:
            str: Sanitized URL
            
        Raises:
            ValueError: If URL is invalid or blocked
        """
        # Validate URL first
        cls.validate_url(url)
        
        # Parse and reconstruct URL to normalize it
        parsed = urlparse(url)
        
        # Reconstruct URL with validated components
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if (scheme == 'http' and ':80' in netloc):
            netloc = netloc.replace(':80', '')
        elif (scheme == 'https' and ':443' in netloc):
            netloc = netloc.replace(':443', '')
        
        sanitized_url = f"{scheme}://{netloc}{parsed.path}"
        
        if parsed.query:
            sanitized_url += f"?{parsed.query}"
        
        logger.info(f"URL sanitized: {url} -> {sanitized_url}")
        return sanitized_url


def validate_external_url(url: str) -> str:
    """
    Convenient function to validate external URLs
    
    Args:
        url: URL to validate
        
    Returns:
        str: Validated and sanitized URL
        
    Raises:
        ValueError: If URL is invalid or blocked
    """
    return SSRFProtection.sanitize_url_for_request(url)


def is_safe_domain(domain: str) -> bool:
    """
    Check if a domain is safe for external requests
    
    Args:
        domain: Domain to check
        
    Returns:
        bool: True if domain is safe
    """
    try:
        # Create a test URL and validate it
        test_url = f"https://{domain}"
        SSRFProtection.validate_url(test_url)
        return True
    except ValueError:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and other attacks
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "file"
    
    # Remove path separators and dangerous characters
    filename = re.sub(r'[^\w\s\.-]', '', filename)
    filename = re.sub(r'[\\/]', '', filename)  # Remove path separators
    filename = re.sub(r'\.\.+', '.', filename)  # Replace multiple dots with single dot
    filename = filename.strip('.')  # Remove leading/trailing dots
    filename = filename.strip()  # Remove whitespace
    
    # Ensure we have a valid filename
    if not filename or filename in ('.', '..'):
        filename = 'file'
    
    return filename 


"""
Security utilities for input validation and output escaping
"""


def escape_html(text: Union[str, None]) -> str:
    """
    Safely escape HTML characters to prevent XSS attacks.
    
    Args:
        text: Input text that may contain HTML characters
        
    Returns:
        HTML-escaped string safe for insertion into HTML content
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def escape_html_attribute(text: Union[str, None]) -> str:
    """
    Escape text for safe insertion into HTML attributes.
    
    Args:
        text: Input text for HTML attribute
        
    Returns:
        Safely escaped string for HTML attributes
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    
    # Escape HTML entities and quotes
    text = html.escape(text, quote=True)
    
    # Additional escaping for attribute context
    text = text.replace("'", "&#x27;")
    text = text.replace("`", "&#x60;")
    
    return text


def sanitize_html_content(content: Union[str, None], allowed_tags: Optional[List[str]] = None) -> str:
    """
    Sanitize HTML content by removing dangerous tags and attributes.
    
    Args:
        content: HTML content to sanitize
        allowed_tags: List of allowed HTML tags (default: none for complete stripping)
        
    Returns:
        Sanitized HTML content
    """
    if content is None:
        return ""
    
    if not isinstance(content, str):
        content = str(content)
    
    if allowed_tags is None:
        # Default: strip all HTML tags, keep text content only
        allowed_tags = []
    
    allowed_attributes = {
        'a': ['href', 'title'],
        'abbr': ['title'],
        'acronym': ['title'],
    }
    
    # Use bleach to sanitize HTML
    sanitized = bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )
    
    return sanitized


def create_safe_html_snippet(template: str, **kwargs) -> str:
    """
    Create a safe HTML snippet by escaping all variables before formatting.
    
    Args:
        template: HTML template string with {variable} placeholders
        **kwargs: Variables to escape and insert into template
        
    Returns:
        Safe HTML with all variables properly escaped
    """
    # Escape all variables
    escaped_kwargs = {}
    for key, value in kwargs.items():
        if isinstance(value, (list, tuple)):
            # Handle lists by escaping each item
            escaped_kwargs[key] = [escape_html(item) for item in value]
        elif isinstance(value, dict):
            # Handle dicts by escaping values
            escaped_kwargs[key] = {k: escape_html(v) for k, v in value.items()}
        else:
            escaped_kwargs[key] = escape_html(value)
    
    return template.format(**escaped_kwargs)


def validate_cve_id(cve_id: str) -> bool:
    """
    Validate CVE ID format to prevent injection attacks.
    
    Args:
        cve_id: CVE identifier to validate
        
    Returns:
        True if valid CVE format, False otherwise
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    
    # CVE format: CVE-YYYY-NNNN (where YYYY is year, NNNN is 4+ digits)
    cve_pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(cve_pattern, cve_id))


def validate_severity_level(severity: str) -> bool:
    """
    Validate vulnerability severity level.
    
    Args:
        severity: Severity level to validate
        
    Returns:
        True if valid severity level, False otherwise
    """
    if not severity or not isinstance(severity, str):
        return False
    
    valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
    return severity.upper() in valid_severities


def sanitize_port_number(port: Union[int, str, None]) -> Optional[int]:
    """
    Validate and sanitize port numbers.
    
    Args:
        port: Port number to validate
        
    Returns:
        Valid port number or None if invalid
    """
    if port is None:
        return None
    
    try:
        port_int = int(port)
        if 1 <= port_int <= 65535:
            return port_int
    except (ValueError, TypeError):
        pass
    
    return None


def sanitize_ip_address(ip: Union[str, None]) -> Optional[str]:
    """
    Validate and sanitize IP addresses.
    
    Args:
        ip: IP address to validate
        
    Returns:
        Valid IP address string or None if invalid
    """
    if not ip or not isinstance(ip, str):
        return None
    
    try:
        # This will raise ValueError if invalid
        ipaddress.ip_address(ip.strip())
        return ip.strip()
    except ValueError:
        return None


def create_vulnerability_badge_html(severity: str, cve_id: str, cvss_score: float) -> str:
    """
    Create safe HTML for vulnerability badges with proper escaping.
    
    Args:
        severity: Vulnerability severity level
        cve_id: CVE identifier
        cvss_score: CVSS score
        
    Returns:
        Safe HTML for vulnerability badges
    """
    # Validate and escape inputs
    severity = escape_html(severity) if validate_severity_level(severity) else "UNKNOWN"
    cve_id = escape_html(cve_id) if validate_cve_id(cve_id) else "INVALID-CVE"
    cvss_score = max(0.0, min(10.0, float(cvss_score))) if cvss_score else 0.0
    
    # Determine CSS classes based on severity
    severity_class = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
        'LOW': 'success'
    }.get(severity, 'secondary')
    
    cvss_class = 'danger' if cvss_score >= 7 else 'warning' if cvss_score >= 4 else 'success'
    
    return f'''
    <div class="vulnerability-badges">
        <span class="badge bg-{severity_class} me-2">{severity}</span>
        <span class="badge bg-{cvss_class} me-2">CVSS {cvss_score:.1f}</span>
        <span class="badge bg-primary me-2">{cve_id}</span>
    </div>
    ''' 


def group_vulnerabilities_by_severity(vulnerabilities: List) -> Dict[str, List]:
    """
    Performance-optimized vulnerability grouping by severity.
    
    Args:
        vulnerabilities: List of vulnerability objects
        
    Returns:
        Dictionary with severity levels as keys and lists of vulnerabilities as values
    """
    groups = {}
    for vuln in vulnerabilities:
        severity = vuln.severity if hasattr(vuln, 'severity') else 'UNKNOWN'
        if severity not in groups:
            groups[severity] = []
        groups[severity].append(vuln)
    return groups


def group_ports_by_state(port_results: List) -> Dict[str, List]:
    """
    Performance-optimized port grouping by state.
    
    Args:
        port_results: List of port scan result objects
        
    Returns:
        Dictionary with port states as keys and lists of ports as values
    """
    groups = {}
    for port in port_results:
        state = port.state if hasattr(port, 'state') else 'unknown'
        if state not in groups:
            groups[state] = []
        groups[state].append(port)
    return groups


def get_open_ports(port_results: List) -> List:
    """
    Performance-optimized function to get only open ports.
    
    Args:
        port_results: List of port scan result objects
        
    Returns:
        List of open ports only
    """
    return [p for p in port_results if hasattr(p, 'state') and p.state == 'open']


def count_vulnerabilities_by_severity(vulnerabilities: List) -> Dict[str, int]:
    """
    Performance-optimized counting of vulnerabilities by severity.
    
    Args:
        vulnerabilities: List of vulnerability objects
        
    Returns:
        Dictionary with severity levels as keys and counts as values
    """
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        severity = vuln.severity if hasattr(vuln, 'severity') else 'UNKNOWN'
        if severity in counts:
            counts[severity] += 1
    return counts


def calculate_risk_metrics(vulnerabilities: List, port_results: List) -> Dict[str, Any]:
    """
    Calculate comprehensive risk metrics with optimized performance.
    
    Args:
        vulnerabilities: List of vulnerability objects
        port_results: List of port scan result objects
        
    Returns:
        Dictionary with calculated risk metrics
    """
    # Group data once for multiple operations
    vuln_groups = group_vulnerabilities_by_severity(vulnerabilities)
    port_groups = group_ports_by_state(port_results)
    
    open_ports = port_groups.get('open', [])
    
    # Count high-risk ports (common attack vectors)
    high_risk_ports = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 27017, 50000}
    high_risk_open_ports = [p for p in open_ports if hasattr(p, 'port') and p.port in high_risk_ports]
    
    return {
        'total_vulnerabilities': len(vulnerabilities),
        'critical_vulnerabilities': len(vuln_groups.get('CRITICAL', [])),
        'high_vulnerabilities': len(vuln_groups.get('HIGH', [])),
        'medium_vulnerabilities': len(vuln_groups.get('MEDIUM', [])),
        'low_vulnerabilities': len(vuln_groups.get('LOW', [])),
        'total_open_ports': len(open_ports),
        'high_risk_open_ports': len(high_risk_open_ports),
        'vulnerability_severity_distribution': {k: len(v) for k, v in vuln_groups.items()},
        'port_state_distribution': {k: len(v) for k, v in port_groups.items()}
    } 