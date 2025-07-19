"""
Configuration management for the Cyber Insurance Scanner
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import validator
from pathlib import Path

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, environment variables should be set manually


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application settings
    app_name: str = "Cyber Insurance Scanner"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 1
    
    # Database settings
    database_url: Optional[str] = None
    redis_url: Optional[str] = None
    
    # Security settings
    secret_key: str = "cyber-insurance-scanner-secret-key-change-in-production"
    api_key: str = "scanner-api-key-change-in-production-12345"
    require_auth: bool = False  # Disabled for testing - ENABLE IN PRODUCTION
    rate_limit_per_minute: int = 60
    
    # Scanning settings - OPTIMIZED FOR MAXIMUM THROUGHPUT
    max_concurrent_scans: int = 15  # Increased from 5 to utilize more CPU
    scan_timeout: int = 300  # 5 minutes
    nmap_timeout: int = 120  # 2 minutes
    subdomain_timeout: int = 180  # 3 minutes
    
    # Asset discovery performance settings - MAXIMIZED PARALLELISM
    dns_concurrency: int = 150  # Increased from 50 - concurrent DNS resolution requests
    http_concurrency: int = 90   # Increased from 30 - concurrent HTTP probes
    asset_discovery_timeout: int = 3  # Reduced from 5 to 3 seconds for faster scanning
    max_subdomains_per_domain: int = 100  # Increased from 50 - more thorough discovery
    
    # Port scanning performance settings
    port_scan_concurrency: int = 20  # NEW: concurrent port scan targets
    nmap_threads: int = 4  # NEW: nmap threading for faster scans
    
    # Port scanning configuration
    default_ports: str = "21,22,23,25,53,80,110,143,443,993,995,3389,5432,3306,1433,6379"
    common_ports: str = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    
    # External service URLs
    crt_sh_url: str = "https://crt.sh"
    cve_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # File storage
    upload_dir: str = "uploads"
    report_dir: str = "reports"
    log_dir: str = "logs"
    
    # Email settings (optional)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    
    # Risk scoring weights
    port_risk_weight: float = 0.3
    vulnerability_risk_weight: float = 0.5
    ssl_risk_weight: float = 0.1
    service_risk_weight: float = 0.1
    
    # OpenAI Configuration for Enhanced Report Generation
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_enabled: bool = False
    
    @validator('upload_dir', 'report_dir', 'log_dir')
    def create_directories(cls, v):
        """Create directories if they don't exist"""
        Path(v).mkdir(parents=True, exist_ok=True)
        return v
    
    @validator('default_ports', 'common_ports')
    def validate_ports(cls, v):
        """Validate port configuration"""
        if not v:
            raise ValueError("Port configuration cannot be empty")
        return v
    
    @property
    def default_port_list(self) -> List[int]:
        """Convert default ports string to list of integers"""
        return self._parse_ports(self.default_ports)
    
    @property
    def common_port_list(self) -> List[int]:
        """Convert common ports string to list of integers"""
        return self._parse_ports(self.common_ports)
    
    def _parse_ports(self, port_string: str) -> List[int]:
        """Parse port string with ranges into list of integers"""
        ports = []
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(list(set(ports)))
    
    @property
    def enhanced_reports_enabled(self) -> bool:
        """Check if enhanced AI reports are enabled and configured"""
        return self.openai_enabled and bool(self.openai_api_key.strip())
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()

# Risk scoring configuration
RISK_CATEGORIES = {
    "low": {"min": 0, "max": 25, "color": "green"},
    "medium": {"min": 26, "max": 50, "color": "yellow"},
    "high": {"min": 51, "max": 75, "color": "orange"},
    "critical": {"min": 76, "max": 100, "color": "red"}
}

# High-risk ports and their associated risks
HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk": 8, "description": "Unencrypted file transfer"},
    22: {"service": "SSH", "risk": 3, "description": "Remote shell access"},
    23: {"service": "Telnet", "risk": 9, "description": "Unencrypted remote access"},
    25: {"service": "SMTP", "risk": 4, "description": "Email server"},
    53: {"service": "DNS", "risk": 2, "description": "Domain name resolution"},
    80: {"service": "HTTP", "risk": 1, "description": "Web server (low risk if redirect-only)"},
    110: {"service": "POP3", "risk": 6, "description": "Unencrypted email retrieval"},
    143: {"service": "IMAP", "risk": 6, "description": "Unencrypted email access"},
    443: {"service": "HTTPS", "risk": 0, "description": "Encrypted web server (secure)"},
    993: {"service": "IMAPS", "risk": 1, "description": "Encrypted email access"},
    995: {"service": "POP3S", "risk": 1, "description": "Encrypted email retrieval"},
    1433: {"service": "MSSQL", "risk": 8, "description": "Microsoft SQL Server"},
    3306: {"service": "MySQL", "risk": 7, "description": "MySQL database"},
    3389: {"service": "RDP", "risk": 9, "description": "Remote desktop access"},
    5432: {"service": "PostgreSQL", "risk": 7, "description": "PostgreSQL database"},
    6379: {"service": "Redis", "risk": 8, "description": "Redis database"}
}

# CVE severity mapping
CVE_SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "NONE": 0
} 

 