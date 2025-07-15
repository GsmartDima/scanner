"""
Security Utilities Module
Provides security functions for SSRF protection, URL validation, and input sanitization
"""
import ipaddress
import socket
import logging
from typing import Set, Union, Optional
from urllib.parse import urlparse
import re

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