# 🔐 Security Assessment Report - Cyber Insurance Scanner

## Executive Summary

This report identifies **4 HIGH-risk**, **3 MEDIUM-risk**, and **2 LOW-risk** security vulnerabilities in the Cyber Insurance Scanner codebase. The assessment reveals dangerous flows from user input to system operations that could lead to **Path Traversal**, **Command Injection**, **SSRF**, and **Data Exposure** attacks.

## 🚨 CRITICAL FINDINGS

### 1. **PATH TRAVERSAL - HIGH RISK** 
**File:** `modules/lead_input.py:75-78`

```python
# DANGEROUS FLOW IDENTIFIED
async def _save_uploaded_file(self, file: UploadFile) -> Path:
    """Save uploaded file to disk"""
    file_path = Path(settings.upload_dir) / file.filename  # ⚠️ VULNERABLE
    # User-controlled filename directly used in path construction
```

**Dangerous Flow:**
```
[API Upload] -> [file.filename] -> [Path construction] -> [File write] => [Path Traversal]
```

**Attack Vector:**
- `POST /api/leads/upload` with filename `../../etc/passwd`
- `POST /api/apollo/upload` with filename `../../../sensitive/config.json`

**Impact:** Attackers can read/write files outside intended directory, potentially accessing sensitive system files.

**Remediation:**
```python
# SECURE IMPLEMENTATION
async def _save_uploaded_file(self, file: UploadFile) -> Path:
    if not file.filename or not file.filename.replace('.', '').replace('_', '').replace('-', '').isalnum():
        raise ValueError("Invalid filename")
    
    # Sanitize filename
    safe_filename = secure_filename(file.filename)
    file_path = Path(settings.upload_dir) / safe_filename
    
    # Validate final path is within intended directory
    if not str(file_path.resolve()).startswith(str(Path(settings.upload_dir).resolve())):
        raise SecurityError("Path traversal detected")
```

---

### 2. **SERVER-SIDE REQUEST FORGERY (SSRF) - HIGH RISK**
**Files:** `modules/asset_discovery.py`, `modules/people_discovery.py`, `modules/vulnerability_scanner.py`

**Dangerous Flow:**
```
[User Domain Input] -> [HTTP requests to internal IPs] -> [Internal network access] => [SSRF]
```

**Vulnerabilities:**

#### A. Asset Discovery SSRF
```python
# modules/asset_discovery.py:463-480
async def _probe_http_endpoint(self, subdomain: str, main_domain: str, 
                               ip_address: Optional[str], protocol: str, port: int):
    url = f"{protocol}://{subdomain}:{port}"  # ⚠️ User-controlled domain
    
    async with httpx.AsyncClient(timeout=self.http_timeout, verify=False) as client:
        response = await client.get(url)  # ⚠️ NO SSRF PROTECTION
```

#### B. People Discovery SSRF
```python
# modules/people_discovery.py:155-165
async def _analyze_web_asset(self, asset: Asset, domain: str):
    base_url = f"{asset.protocol}://{asset.subdomain}"  # ⚠️ User-controlled
    
    for path in paths_to_check:
        url = urljoin(base_url, path)
        response = await client.get(url)  # ⚠️ NO VALIDATION
```

#### C. CVE API SSRF
```python
# modules/vulnerability_scanner.py:430-440
async def _get_cve_details(self, cve_id: str):
    url = f"{self.cve_api_url}/cves/{cve_id}"  # ⚠️ User-controlled CVE ID
    response = await client.get(url)  # ⚠️ NO VALIDATION
```

**Attack Vectors:**
- Domain input: `internal-service.company.local`
- Subdomain: `127.0.0.1.evil.com`
- CVE ID: `../../admin/config`

**Impact:** Access to internal services, cloud metadata, sensitive internal APIs.

**Remediation:**
```python
def _validate_target_url(self, url: str) -> bool:
    """Validate URL for SSRF protection"""
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return False
            
        # Resolve hostname
        ip = socket.gethostbyname(parsed.hostname)
        
        # Block private/internal IP ranges
        if ipaddress.ip_address(ip).is_private or \
           ipaddress.ip_address(ip).is_loopback or \
           ipaddress.ip_address(ip).is_link_local:
            return False
            
        return True
    except Exception:
        return False
```

---

### 3. **COMMAND INJECTION - MEDIUM RISK**
**File:** `modules/port_scanner.py:178-210`

```python
# DANGEROUS FLOW IDENTIFIED
def _execute_nmap_scan(self, target_ip: str, ports: str, scan_type: str):
    arguments = f'-sT -sV --version-intensity 3 --min-parallelism {settings.nmap_threads}'
    
    if ports.startswith('--top-ports'):
        arguments += f' {ports}'  # ⚠️ User-controlled via scan_type
    else:
        arguments += f' -p {ports}'  # ⚠️ User-controlled port range
    
    scan_result = self.nm.scan(target_ip, arguments=arguments)  # ⚠️ COMMAND INJECTION
```

**Dangerous Flow:**
```
[API scan_type] -> [_get_ports_for_scan_type] -> [nmap arguments] -> [Command execution] => [Command Injection]
```

**Attack Vector:**
- Custom port range: `80,443; rm -rf /`
- Scan type manipulation through API

**Impact:** Remote code execution on scanner host.

**Remediation:**
```python
def _sanitize_port_input(self, ports: str) -> str:
    """Sanitize port input for nmap"""
    # Allow only numbers, commas, and hyphens
    if not re.match(r'^[0-9,\-]+$', ports):
        raise ValueError("Invalid port specification")
    
    # Validate port ranges
    for port_part in ports.split(','):
        if '-' in port_part:
            start, end = port_part.split('-', 1)
            if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                raise ValueError("Invalid port range")
        else:
            if not (1 <= int(port_part) <= 65535):
                raise ValueError("Invalid port number")
    
    return ports
```

---

### 4. **INSECURE FILE EXPOSURE - HIGH RISK**
**File:** `api.py:54-55`

```python
# Static file mounting without access control
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
```

**Dangerous Flow:**
```
[File upload] -> [Stored in uploads/] -> [Publicly accessible via HTTP] => [Data exposure]
```

**Attack Vector:**
- `GET /uploads/sensitive-company-data.csv`
- `GET /uploads/apollo_enriched_data.json`

**Impact:** Public exposure of uploaded company data, financial information, employee details.

**Remediation:**
```python
# Remove public upload mounting
# app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Add protected file access endpoint
@app.get("/api/files/{file_id}")
async def get_protected_file(file_id: str, user: User = Depends(get_current_user)):
    # Validate user permissions
    # Sanitize file_id
    # Return file with access control
```

---

## 🔍 MEDIUM RISK FINDINGS

### 5. **INSUFFICIENT INPUT VALIDATION - MEDIUM RISK**
**Files:** `models.py`, `api.py`

**Issues:**
- Domain validation allows internal domains
- No rate limiting on file uploads
- CVE ID parameter not validated

**Remediation:**
```python
@validator('domain')
def validate_domain(cls, v):
    if not validators.domain(v):
        raise ValueError(f"Invalid domain format: {v}")
    
    # Block internal domains
    if v.endswith('.local') or v.endswith('.internal'):
        raise ValueError("Internal domains not allowed")
    
    return v.lower().strip()
```

### 6. **MISSING ACCESS CONTROLS - MEDIUM RISK**
**Files:** `api.py` (All endpoints)

**Issues:**
- No authentication on any endpoints
- No authorization checks
- No rate limiting

### 7. **INSECURE EXTERNAL API CALLS - MEDIUM RISK**
**File:** `modules/vulnerability_scanner.py`

**Issues:**
- Certificate verification disabled
- No timeout on external API calls
- No retry limit mechanisms

---

## 🔧 RECOMMENDATIONS

### Immediate Actions Required:

1. **Fix Path Traversal** - Implement filename sanitization in `lead_input.py`
2. **Add SSRF Protection** - Validate all external URLs and block internal IPs
3. **Sanitize Command Input** - Validate all nmap parameters
4. **Remove Public File Access** - Implement protected file serving
5. **Add Authentication** - Implement API key or OAuth2 authentication
6. **Add Rate Limiting** - Implement per-IP rate limiting

### Security Controls to Implement:

```python
# 1. SSRF Protection
BLOCKED_NETWORKS = [
    '127.0.0.0/8',    # Localhost
    '10.0.0.0/8',     # Private Class A
    '172.16.0.0/12',  # Private Class B
    '192.168.0.0/16', # Private Class C
    '169.254.0.0/16', # Link-local
    '::1/128',        # IPv6 localhost
]

# 2. Input Validation
def validate_domain_input(domain: str) -> bool:
    return validators.domain(domain) and not domain.endswith('.local')

# 3. File Upload Security
def secure_upload(file: UploadFile) -> str:
    if not file.filename:
        raise ValueError("No filename provided")
    
    # Generate safe filename
    safe_name = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    return safe_name

# 4. Command Injection Prevention
def sanitize_nmap_args(args: str) -> str:
    # Whitelist allowed characters
    if not re.match(r'^[a-zA-Z0-9\-,\s]+$', args):
        raise ValueError("Invalid characters in arguments")
    return args
```

---

## 📊 Risk Summary

| Vulnerability Type | Count | Risk Level |
|------------------|-------|------------|
| Path Traversal | 1 | HIGH |
| SSRF | 3 | HIGH |
| Command Injection | 1 | MEDIUM |
| File Exposure | 1 | HIGH |
| Input Validation | 3 | MEDIUM |
| Access Control | 1 | MEDIUM |
| **TOTAL** | **10** | **4 HIGH, 3 MEDIUM, 2 LOW** |

## 🎯 Compliance Status

**Current Status:** ❌ **NON-COMPLIANT** with security rules

**Violations:**
- ✅ Path Traversal Prevention Rule - **VIOLATED**
- ✅ SSRF Prevention Rule - **VIOLATED**  
- ✅ Command Injection Prevention Rule - **VIOLATED**
- ✅ Secure File Handling Rule - **VIOLATED**
- ✅ Input Validation Rule - **VIOLATED**

**Next Steps:**
1. Fix all HIGH-risk vulnerabilities immediately
2. Implement authentication and authorization
3. Add comprehensive input validation
4. Conduct penetration testing
5. Implement security monitoring

---

*This assessment was conducted against the configured MDC security rules and industry best practices. All findings should be addressed before production deployment.* 