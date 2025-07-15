# 🔧 Security Fix Action Plan - Immediate Actions Required

## 🚨 PHASE 1: Critical Security Fixes (DO IMMEDIATELY)

### 1. Fix Path Traversal Vulnerability
**Priority:** CRITICAL  
**File:** `modules/lead_input.py`  
**Timeline:** Fix within 24 hours

```python
# Add to requirements.txt
werkzeug>=2.0.0

# Replace _save_uploaded_file method
import uuid
from werkzeug.utils import secure_filename

async def _save_uploaded_file(self, file: UploadFile) -> Path:
    """Save uploaded file to disk with path traversal protection"""
    if not file.filename:
        raise ValueError("No filename provided")
    
    # Validate filename format
    if not file.filename.replace('.', '').replace('_', '').replace('-', '').isalnum():
        raise ValueError("Invalid filename format")
    
    # Generate safe filename with UUID prefix
    safe_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    file_path = Path(settings.upload_dir) / safe_filename
    
    # Validate final path is within intended directory
    upload_dir_resolved = Path(settings.upload_dir).resolve()
    file_path_resolved = file_path.resolve()
    
    if not str(file_path_resolved).startswith(str(upload_dir_resolved)):
        raise SecurityError("Path traversal attack detected")
    
    async with aiofiles.open(file_path, 'wb') as f:
        content = await file.read()
        await f.write(content)
    
    return file_path
```

### 2. Remove Public File Exposure
**Priority:** CRITICAL  
**File:** `api.py`  
**Timeline:** Fix within 24 hours

```python
# REMOVE this line from api.py:55
# app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# ADD protected file access endpoint
from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse

# Simple API key authentication (implement proper auth later)
def verify_api_key(api_key: str = Header(None)):
    if api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

@app.get("/api/files/{file_id}")
async def get_protected_file(file_id: str, api_key: str = Depends(verify_api_key)):
    """Serve files with access control"""
    # Validate file_id format
    if not re.match(r'^[a-f0-9\-]+_[a-zA-Z0-9._-]+$', file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID")
    
    file_path = Path(settings.upload_dir) / file_id
    
    # Validate path is within uploads directory
    if not str(file_path.resolve()).startswith(str(Path(settings.upload_dir).resolve())):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(path=file_path)
```

### 3. Add SSRF Protection
**Priority:** CRITICAL  
**Files:** `modules/asset_discovery.py`, `modules/people_discovery.py`, `modules/vulnerability_scanner.py`  
**Timeline:** Fix within 48 hours

```python
# Create new file: modules/security_utils.py
import socket
import ipaddress
from urllib.parse import urlparse
from typing import List

class SSRFProtection:
    """SSRF protection utilities"""
    
    BLOCKED_NETWORKS = [
        '127.0.0.0/8',      # Localhost
        '10.0.0.0/8',       # Private Class A
        '172.16.0.0/12',    # Private Class B
        '192.168.0.0/16',   # Private Class C
        '169.254.0.0/16',   # Link-local
        '::1/128',          # IPv6 localhost
        'fc00::/7',         # IPv6 unique local
        'fe80::/10',        # IPv6 link-local
    ]
    
    BLOCKED_DOMAINS = [
        'localhost',
        'metadata.google.internal',
        '169.254.169.254',  # AWS metadata
        'metadata.gce.internal',
    ]
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Validate URL against SSRF attacks"""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False
            
            # Block known dangerous hostnames
            if parsed.hostname.lower() in cls.BLOCKED_DOMAINS:
                return False
            
            # Block internal domains
            if parsed.hostname.endswith('.local') or parsed.hostname.endswith('.internal'):
                return False
            
            # Resolve hostname to IP
            try:
                ip_str = socket.gethostbyname(parsed.hostname)
                ip = ipaddress.ip_address(ip_str)
            except (socket.gaierror, ValueError):
                return False
            
            # Check against blocked networks
            for network_str in cls.BLOCKED_NETWORKS:
                network = ipaddress.ip_network(network_str)
                if ip in network:
                    return False
            
            return True
            
        except Exception:
            return False

# Update modules to use SSRF protection
# In asset_discovery.py, people_discovery.py, vulnerability_scanner.py:
from modules.security_utils import SSRFProtection

# Before making HTTP requests:
if not SSRFProtection.validate_url(url):
    logger.warning(f"SSRF protection blocked request to: {url}")
    return None
```

### 4. Add Command Injection Protection
**Priority:** HIGH  
**File:** `modules/port_scanner.py`  
**Timeline:** Fix within 48 hours

```python
import re

def _sanitize_port_input(self, ports: str) -> str:
    """Sanitize port input to prevent command injection"""
    # Remove any whitespace
    ports = ports.strip()
    
    # Allow only numbers, commas, and hyphens for port ranges
    if not re.match(r'^[0-9,\-]+$', ports):
        raise ValueError(f"Invalid port specification: {ports}")
    
    # Validate individual port numbers and ranges
    for port_part in ports.split(','):
        port_part = port_part.strip()
        if '-' in port_part:
            # Port range
            try:
                start, end = port_part.split('-', 1)
                start_port, end_port = int(start), int(end)
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                    raise ValueError(f"Invalid port range: {port_part}")
                if start_port > end_port:
                    raise ValueError(f"Invalid port range order: {port_part}")
            except ValueError as e:
                raise ValueError(f"Invalid port range format: {port_part}")
        else:
            # Single port
            try:
                port_num = int(port_part)
                if not (1 <= port_num <= 65535):
                    raise ValueError(f"Invalid port number: {port_part}")
            except ValueError:
                raise ValueError(f"Invalid port format: {port_part}")
    
    return ports

def _get_ports_for_scan_type(self, scan_type: str) -> str:
    """Get port range based on scan type with validation"""
    # Whitelist allowed scan types
    allowed_scan_types = ["default", "common", "top100", "top1000"]
    if scan_type not in allowed_scan_types:
        raise ValueError(f"Invalid scan type: {scan_type}")
    
    if scan_type == "default":
        ports = ','.join(map(str, settings.default_port_list))
    elif scan_type == "common":
        ports = ','.join(map(str, settings.common_port_list))
    elif scan_type == "top100":
        ports = "--top-ports 100"
    elif scan_type == "top1000":
        ports = "--top-ports 1000"
    
    # Validate ports if not using --top-ports
    if not ports.startswith('--top-ports'):
        ports = self._sanitize_port_input(ports)
    
    return ports
```

---

## 🔒 PHASE 2: Authentication & Authorization (Week 1)

### 1. Add API Authentication
**File:** `api.py`

```python
# Add to config.py
class Settings(BaseSettings):
    # ... existing settings ...
    api_key: str = "change-this-in-production"
    require_auth: bool = True

# Add to api.py
from functools import wraps
from fastapi import Header, HTTPException

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        # Extract API key from headers
        api_key = kwargs.get('api_key') or request.headers.get('X-API-Key')
        
        if settings.require_auth and api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        
        return await f(*args, **kwargs)
    return decorated_function

# Apply to all sensitive endpoints
@app.post("/api/scan/start")
@require_api_key
async def start_scan(scan_request: ScanRequest, api_key: str = Header(None, alias="X-API-Key")):
    # ... existing code ...
```

### 2. Add Rate Limiting
**File:** `api.py`

```python
# Add to requirements.txt
slowapi>=0.1.5

# Add to api.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Apply rate limiting to endpoints
@app.post("/api/scan/start")
@limiter.limit("5/minute")  # 5 scans per minute per IP
async def start_scan(request: Request, scan_request: ScanRequest):
    # ... existing code ...

@app.post("/api/leads/upload")
@limiter.limit("10/hour")  # 10 file uploads per hour per IP
async def upload_leads_file(request: Request, file: UploadFile = File(...)):
    # ... existing code ...
```

---

## 🛡️ PHASE 3: Enhanced Security (Week 2)

### 1. Input Validation Enhancement
**File:** `models.py`

```python
@validator('domain')
def validate_domain(cls, v):
    """Enhanced domain validation"""
    # Basic format validation
    if not validators.domain(v):
        raise ValueError(f"Invalid domain format: {v}")
    
    # Block internal/private domains
    blocked_tlds = ['.local', '.internal', '.corp', '.lan']
    if any(v.lower().endswith(tld) for tld in blocked_tlds):
        raise ValueError("Internal domains not allowed")
    
    # Block localhost variations
    if v.lower() in ['localhost', '127.0.0.1', '::1']:
        raise ValueError("Localhost not allowed")
    
    # Length validation
    if len(v) > 253:  # RFC maximum domain length
        raise ValueError("Domain name too long")
    
    return v.lower().strip()
```

### 2. Secure External API Calls
**File:** `modules/vulnerability_scanner.py`

```python
async def _get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
    """Get CVE details with security validations"""
    # Validate CVE ID format
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        logger.warning(f"Invalid CVE ID format: {cve_id}")
        return None
    
    # Check cache first
    cache_key = f"{cve_id}_{datetime.now().date()}"
    if cache_key in self.cve_cache:
        cached_data = self.cve_cache[cache_key]
        if datetime.now() - cached_data['timestamp'] < self.cache_ttl:
            return cached_data['data']
    
    # Validate URL before making request
    url = f"{self.cve_api_url}/cves/{cve_id}"
    if not SSRFProtection.validate_url(url):
        logger.error(f"SSRF protection blocked CVE API request: {url}")
        return None
    
    try:
        async with httpx.AsyncClient(
            timeout=self.http_timeout,
            verify=True,  # Enable certificate verification
            follow_redirects=False  # Don't follow redirects
        ) as client:
            response = await client.get(url)
            # ... rest of implementation
```

---

## 📋 Implementation Checklist

### Immediate (24-48 hours)
- [ ] Fix path traversal in file uploads
- [ ] Remove public file access 
- [ ] Add SSRF protection utilities
- [ ] Implement command injection protection
- [ ] Add basic API key authentication

### Week 1
- [ ] Implement rate limiting
- [ ] Add comprehensive logging for security events
- [ ] Create security middleware
- [ ] Add input validation for all endpoints

### Week 2
- [ ] Implement proper authentication system
- [ ] Add authorization controls
- [ ] Security testing and validation
- [ ] Documentation updates

### Testing
- [ ] Test path traversal protection with `../../../etc/passwd`
- [ ] Test SSRF protection with `127.0.0.1`, `metadata.google.internal`
- [ ] Test command injection with malicious port ranges
- [ ] Verify file access requires authentication
- [ ] Test rate limiting enforcement

---

## 🚨 Security Monitoring

Add these security event logs:

```python
# Add to api.py
import logging

security_logger = logging.getLogger('security')
security_handler = logging.FileHandler('logs/security.log')
security_logger.addHandler(security_handler)

# Log security events
def log_security_event(event_type: str, details: str, client_ip: str):
    security_logger.warning(f"SECURITY_EVENT: {event_type} | IP: {client_ip} | {details}")

# Use in endpoints:
log_security_event("UPLOAD_ATTEMPT", f"File: {file.filename}", get_client_ip(request))
log_security_event("SCAN_REQUEST", f"Domain: {domain}", get_client_ip(request))
```

This action plan prioritizes the most critical vulnerabilities and provides concrete implementation steps. **Start with Phase 1 immediately** - these are the vulnerabilities that pose the highest risk to your system. 