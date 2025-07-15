"""
Port Scanning Module
Handles port scanning using Nmap for service detection and OS fingerprinting
"""
import asyncio
import nmap
import socket
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import subprocess
import re
import ipaddress

from models import PortScanResult, Lead, Asset
from config import settings, HIGH_RISK_PORTS

logger = logging.getLogger(__name__)


class PortScanner:
    """Port scanner using Nmap for comprehensive scanning"""
    
    def __init__(self):
        self.timeout = settings.nmap_timeout
        self.nm = nmap.PortScanner()
        
        # Check if nmap is available
        try:
            self.nm.nmap_version()
            logger.info(f"Nmap version: {self.nm.nmap_version()}")
        except Exception as e:
            logger.error(f"Nmap not available: {str(e)}")
            raise RuntimeError("Nmap is required but not available")
    
    async def scan_domain_ports(self, lead: Lead, assets: List[Asset], 
                               scan_type: str = "default") -> List[PortScanResult]:
        """Scan ports for a domain and its assets with maximum parallelization"""
        logger.info(f"Starting optimized port scan for {lead.domain} with {len(assets)} assets")
        
        targets = set()
        
        # Get all unique IP addresses from assets
        for asset in assets:
            if asset.ip_address:
                targets.add(asset.ip_address)
        
        # Also resolve main domain IP
        main_ip = await self._resolve_domain_ip(lead.domain)
        if main_ip:
            targets.add(main_ip)
        
        # Remove invalid IPs
        valid_targets = [ip for ip in targets if self._is_valid_ip(ip)]
        
        if not valid_targets:
            logger.warning(f"No valid IP targets found for {lead.domain}")
            return []
        
        # Determine ports to scan
        ports = self._get_ports_for_scan_type(scan_type)
        
        # OPTIMIZED: Scan all targets in parallel using concurrency control
        semaphore = asyncio.Semaphore(settings.port_scan_concurrency)
        
        async def scan_target_with_semaphore(target_ip):
            async with semaphore:
                return await self._scan_target(target_ip, lead.domain, ports, scan_type)
        
        # Create scanning tasks for all targets
        scan_tasks = [scan_target_with_semaphore(target_ip) for target_ip in valid_targets]
        
        # Execute all scans in parallel
        logger.debug(f"Executing {len(scan_tasks)} parallel port scans with concurrency limit of {settings.port_scan_concurrency}")
        results_lists = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Combine all results
        results = []
        for i, result in enumerate(results_lists):
            if isinstance(result, Exception):
                logger.error(f"Failed to scan target {valid_targets[i]}: {str(result)}")
            else:
                results.extend(result)
        
        logger.info(f"Optimized port scan completed for {lead.domain}: {len(results)} results from {len(valid_targets)} targets")
        return results
    
    async def _resolve_domain_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            logger.debug(f"Failed to resolve {domain}: {str(e)}")
            return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid and not private/localhost"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            
            # Skip localhost and private ranges for external scanning
            if ip.startswith('127.') or ip.startswith('10.') or \
               ip.startswith('192.168.') or ip.startswith('172.'):
                return False
            
            return True
        except Exception:
            return False
    
    def _validate_ip_for_command_injection(self, ip: str) -> bool:
        """
        Validate IP address to prevent command injection attacks
        
        Args:
            ip: IP address to validate
            
        Returns:
            bool: True if IP is safe for command execution
            
        Raises:
            ValueError: If IP is invalid or contains malicious patterns
        """
        if not ip or not isinstance(ip, str):
            raise ValueError("Invalid IP address: empty or not a string")
        
        # Check for command injection patterns
        dangerous_patterns = [
            ';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', 
            '\n', '\r', '\t', ' ', 'rm', 'cat', 'ls', 'wget', 'curl', 'nc'
        ]
        
        ip_lower = ip.lower()
        for pattern in dangerous_patterns:
            if pattern in ip_lower:
                logger.error(f"Command injection attempt detected in IP: {ip}")
                raise ValueError(f"Invalid IP address: contains dangerous pattern '{pattern}'")
        
        # Validate IP format using ipaddress module
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Additional security checks
            if ip_obj.is_private:
                logger.warning(f"Private IP address detected: {ip}")
                raise ValueError("Private IP addresses are not allowed")
            
            if ip_obj.is_loopback:
                logger.warning(f"Loopback IP address detected: {ip}")
                raise ValueError("Loopback IP addresses are not allowed")
            
            if ip_obj.is_multicast:
                logger.warning(f"Multicast IP address detected: {ip}")
                raise ValueError("Multicast IP addresses are not allowed")
            
            logger.debug(f"IP validation passed: {ip}")
            return True
            
        except ipaddress.AddressValueError:
            logger.error(f"Invalid IP address format: {ip}")
            raise ValueError(f"Invalid IP address format: {ip}")
        except Exception as e:
            logger.error(f"IP validation error: {str(e)}")
            raise ValueError(f"IP validation failed: {str(e)}")
    
    def _get_ports_for_scan_type(self, scan_type: str) -> str:
        """Get port range based on scan type"""
        if scan_type == "default":
            return ','.join(map(str, settings.default_port_list))
        elif scan_type == "common":
            return ','.join(map(str, settings.common_port_list))
        elif scan_type == "top100":
            return "--top-ports 100"
        elif scan_type == "top1000":
            return "--top-ports 1000"
        else:
            return ','.join(map(str, settings.default_port_list))
    
    async def _scan_target(self, target_ip: str, domain: str, ports: str, 
                          scan_type: str) -> List[PortScanResult]:
        """Scan a specific target IP"""
        results = []
        
        try:
            # Run scan in executor to avoid blocking
            scan_result = await asyncio.get_event_loop().run_in_executor(
                None, self._execute_nmap_scan, target_ip, ports, scan_type
            )
            
            if target_ip in scan_result.all_hosts():
                host_info = scan_result[target_ip]
                
                # Extract OS information
                os_info = self._extract_os_info(host_info)
                
                # Process each scanned port
                for protocol in host_info.all_protocols():
                    ports_info = host_info[protocol].keys()
                    
                    for port in ports_info:
                        port_info = host_info[protocol][port]
                        
                        port_result = PortScanResult(
                            domain=domain,
                            ip_address=target_ip,
                            port=port,
                            protocol=protocol,
                            state=port_info['state'],
                            service=port_info.get('name', ''),
                            version=self._format_version_info(port_info),
                            banner=port_info.get('extrainfo', ''),
                            os_info=os_info,
                            scanned_at=datetime.now()
                        )
                        
                        results.append(port_result)
                        
                        # Log high-risk ports
                        if port in HIGH_RISK_PORTS and port_info['state'] == 'open':
                            risk_info = HIGH_RISK_PORTS[port]
                            logger.warning(f"High-risk port {port} ({risk_info['service']}) open on {target_ip}")
        
        except Exception as e:
            logger.error(f"Nmap scan failed for {target_ip}: {str(e)}")
        
        return results
    
    def _execute_nmap_scan(self, target_ip: str, ports: str, scan_type: str) -> Any:
        """Execute the actual Nmap scan with optimized performance settings and security validation"""
        try:
            # SECURITY: Validate IP address to prevent command injection
            self._validate_ip_for_command_injection(target_ip)
            
            # OPTIMIZED: Use aggressive timing and threading for maximum speed
            arguments = f'-sT -sV --version-intensity 3 --min-parallelism {settings.nmap_threads}'
            
            # Add aggressive timing template for maximum speed
            arguments += ' -T5'  # Increased from T4 to T5 for maximum speed
            
            # Optimize timeouts for faster scanning
            arguments += f' --host-timeout {self.timeout//2}s'  # Reduced timeout
            arguments += ' --max-rtt-timeout 500ms'  # Fast RTT timeout
            arguments += ' --initial-rtt-timeout 250ms'  # Fast initial RTT
            
            # Skip host discovery for single IP
            arguments += ' -Pn'
            
            # Disable reverse DNS lookup for speed
            arguments += ' -n'
            
            # OPTIMIZED: Add parallel scanning options
            arguments += f' --max-scan-delay 0'  # No delay between probes
            arguments += f' --min-rate 1000'  # Minimum packet rate for speed
            
            # Determine port specification
            if ports.startswith('--top-ports'):
                arguments += f' {ports}'
            else:
                arguments += f' -p {ports}'
            
            # Execute scan
            logger.debug(f"Executing optimized nmap scan: {target_ip} with args: {arguments}")
            
            scan_result = self.nm.scan(target_ip, arguments=arguments)
            return self.nm
            
        except Exception as e:
            logger.error(f"Optimized nmap execution error: {str(e)}")
            # Try fallback with less aggressive settings
            try:
                logger.info("Attempting fallback scan with moderate settings")
                # SECURITY: Re-validate IP address for fallback scan
                self._validate_ip_for_command_injection(target_ip)
                
                fallback_args = f'-sT -T4 --host-timeout {self.timeout}s -Pn -n'
                if ports.startswith('--top-ports'):
                    fallback_args += f' {ports}'
                else:
                    fallback_args += f' -p {ports}'
                
                scan_result = self.nm.scan(target_ip, arguments=fallback_args)
                return self.nm
            except Exception as fallback_error:
                logger.error(f"Fallback scan also failed: {str(fallback_error)}")
                raise
    
    def _extract_os_info(self, host_info: Dict[str, Any]) -> Optional[str]:
        """Extract OS information from scan results"""
        try:
            if 'osmatch' in host_info:
                os_matches = host_info['osmatch']
                if os_matches:
                    # Get the best match
                    best_match = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
                    return f"{best_match.get('name', '')} (accuracy: {best_match.get('accuracy', 0)}%)"
            
            # Fallback to osclass information
            if 'osclass' in host_info:
                os_classes = host_info['osclass']
                if os_classes:
                    best_class = max(os_classes, key=lambda x: int(x.get('accuracy', 0)))
                    return f"{best_class.get('vendor', '')} {best_class.get('osfamily', '')} {best_class.get('osgen', '')}"
            
        except Exception as e:
            logger.debug(f"Error extracting OS info: {str(e)}")
        
        return None
    
    def _format_version_info(self, port_info: Dict[str, Any]) -> Optional[str]:
        """Format service version information"""
        try:
            version_parts = []
            
            if port_info.get('product'):
                version_parts.append(port_info['product'])
            
            if port_info.get('version'):
                version_parts.append(port_info['version'])
            
            if version_parts:
                return ' '.join(version_parts)
            
        except Exception:
            pass
        
        return None
    
    async def quick_port_check(self, domain: str, ports: List[int]) -> List[PortScanResult]:
        """Quick port connectivity check without service detection"""
        results = []
        
        # Resolve domain
        ip_address = await self._resolve_domain_ip(domain)
        if not ip_address:
            return results
        
        # Check each port
        for port in ports:
            is_open = await self._check_port_connectivity(ip_address, port)
            
            if is_open:
                result = PortScanResult(
                    domain=domain,
                    ip_address=ip_address,
                    port=port,
                    protocol="tcp",
                    state="open",
                    scanned_at=datetime.now()
                )
                results.append(result)
        
        return results
    
    async def _check_port_connectivity(self, ip: str, port: int, timeout: int = 5) -> bool:
        """Check if a specific port is open using socket connection"""
        try:
            # Use asyncio for non-blocking socket operations
            future = asyncio.get_event_loop().run_in_executor(
                None, self._socket_connect, ip, port, timeout
            )
            return await asyncio.wait_for(future, timeout=timeout + 1)
        except Exception:
            return False
    
    def _socket_connect(self, ip: str, port: int, timeout: int) -> bool:
        """Perform socket connection test"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def analyze_scan_results(self, results: List[PortScanResult]) -> Dict[str, Any]:
        """Analyze port scan results for risk assessment"""
        analysis = {
            'total_open_ports': 0,
            'high_risk_ports': [],
            'services_detected': {},
            'os_fingerprints': [],
            'security_concerns': []
        }
        
        for result in results:
            if result.state == 'open':
                analysis['total_open_ports'] += 1
                
                # Check for high-risk ports
                if result.port in HIGH_RISK_PORTS:
                    risk_info = HIGH_RISK_PORTS[result.port]
                    analysis['high_risk_ports'].append({
                        'port': result.port,
                        'service': risk_info['service'],
                        'risk_level': risk_info['risk'],
                        'description': risk_info['description'],
                        'detected_service': result.service,
                        'version': result.version
                    })
                
                # Track services
                if result.service:
                    if result.service not in analysis['services_detected']:
                        analysis['services_detected'][result.service] = 0
                    analysis['services_detected'][result.service] += 1
                
                # Track OS fingerprints
                if result.os_info and result.os_info not in analysis['os_fingerprints']:
                    analysis['os_fingerprints'].append(result.os_info)
        
        # Generate security concerns
        if analysis['high_risk_ports']:
            analysis['security_concerns'].append(
                f"Found {len(analysis['high_risk_ports'])} high-risk open ports"
            )
        
        if analysis['total_open_ports'] > 20:
            analysis['security_concerns'].append(
                f"Large attack surface: {analysis['total_open_ports']} open ports"
            )
        
        # Check for common vulnerable services
        vulnerable_services = ['ftp', 'telnet', 'rlogin', 'rsh']
        for service in vulnerable_services:
            if service in analysis['services_detected']:
                analysis['security_concerns'].append(
                    f"Insecure service detected: {service.upper()}"
                )
        
        return analysis 