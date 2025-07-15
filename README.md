# Cyber Insurance Scanner

> **Automated Cybersecurity Risk Assessment for Insurance Companies**

A comprehensive Python application that automates the scanning and risk evaluation process for potential clients (leads) of a cybersecurity insurance company. Each lead represents a domain/company, and the software discovers publicly exposed services, scans open ports, assesses vulnerabilities, and assigns security risk scores.

## 🌟 Features

### Core Scanning Capabilities
- **Asset Discovery**: DNS enumeration, subdomain discovery, HTTP(S) probing
- **Port Scanning**: Comprehensive port scanning using Nmap with service detection
- **Vulnerability Assessment**: CVE matching and vulnerability analysis
- **Risk Scoring**: Multi-factor risk scoring engine with categorization
- **Batch Processing**: Support for scanning multiple domains concurrently

### Input Methods
- **File Upload**: CSV, JSON, and Excel file support
- **REST API**: Full RESTful API for programmatic access
- **Command Line**: Rich CLI interface with progress indicators
- **Web Interface**: Interactive API documentation via FastAPI

### Output Formats
- **JSON**: Structured data export
- **CSV**: Tabular reports for spreadsheet analysis
- **Executive Reports**: High-level summaries for management
- **Real-time API**: Live results via HTTP endpoints

### Security & Compliance
- Rate limiting and ethical scanning practices
- Comprehensive audit logging
- Configurable scan intensity and timeouts
- Support for authorized domain lists only

## 📋 Requirements

### System Requirements
- **Python**: 3.8+ 
- **Nmap**: Required for port scanning (`apt-get install nmap` or `brew install nmap`)
- **Memory**: 2GB+ RAM recommended for concurrent scanning
- **Storage**: 1GB+ for logs and results storage

### Network Requirements
- Internet access for vulnerability database queries
- DNS resolution capabilities
- Optional: Access to internal networks for comprehensive scanning

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd scanner

# Install dependencies
pip install -r requirements.txt

# Verify Nmap installation
nmap --version
```

### 2. Configuration

Create a `.env` file or modify `config.py` settings:

```bash
# Basic configuration
APP_NAME="Cyber Insurance Scanner"
DEBUG=false
MAX_CONCURRENT_SCANS=5

# API settings
API_HOST=0.0.0.0
API_PORT=8000

# Scanning configuration
NMAP_TIMEOUT=300
SUBDOMAIN_TIMEOUT=60
CVE_API_URL="https://services.nvd.nist.gov/rest/json"

# Risk scoring weights
PORT_RISK_WEIGHT=0.25
VULNERABILITY_RISK_WEIGHT=0.35
SSL_RISK_WEIGHT=0.20
SERVICE_RISK_WEIGHT=0.20
```

### 3. Basic Usage

#### Command Line Interface

```bash
# Quick scan of a single domain
python cli.py quick-scan example.com --company "Example Corp" --output results.json

# Comprehensive full scan
python cli.py full-scan example.com --output results.csv --format csv

# Batch scanning from CSV file
python cli.py batch-scan domains.csv --output ./results --scan-type full

# Start web server
python cli.py serve --port 8000
```

#### API Server

```bash
# Start the API server
python api.py

# Or using the CLI
python cli.py serve
```

Access the interactive API documentation at: `http://localhost:8000/docs`

#### Python Integration

```python
import asyncio
from models import Lead
from modules.scanner_orchestrator import ScannerOrchestrator

async def scan_domain():
    scanner = ScannerOrchestrator()
    lead = Lead(domain="example.com", company_name="Example Corp")
    
    # Quick scan
    result = await scanner.quick_scan(lead)
    print(f"Risk Score: {result.risk_score.overall_score}")
    
    # Full scan
    result = await scanner.full_scan(lead)
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")

# Run the scan
asyncio.run(scan_domain())
```

## 📚 Documentation

### Architecture Overview

The scanner follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Input Layer   │    │  Processing      │    │  Output Layer   │
│                 │    │  Layer          │    │                 │
│ • CLI Interface │    │ • Asset Discovery│    │ • JSON Export   │
│ • REST API      │───▶│ • Port Scanning  │───▶│ • CSV Reports   │
│ • File Upload   │    │ • Vuln Assessment│    │ • Risk Scores   │
│ • Lead Mgmt     │    │ • Risk Engine    │    │ • Analytics     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Modules

#### 1. Lead Input Module (`modules/lead_input.py`)
- **Purpose**: Handles lead ingestion and validation
- **Input Methods**: CSV, JSON, Excel file processing
- **Features**: Domain validation, duplicate removal, batch processing
- **Schema**: Domain (FQDN), Company Name, Timestamp

#### 2. Asset Discovery Module (`modules/asset_discovery.py`)
- **Purpose**: Discovers all assets associated with a domain
- **Capabilities**:
  - DNS enumeration (A, AAAA, CNAME, MX, TXT, NS records)
  - Subdomain discovery via multiple techniques
  - HTTP(S) service probing and technology detection
- **Techniques**:
  - Common subdomain bruteforcing
  - Certificate transparency log analysis
  - DNS zone transfer attempts
- **Output**: List of discovered assets with metadata

#### 3. Port Scanning Module (`modules/port_scanner.py`)
- **Purpose**: Comprehensive port scanning and service detection
- **Tools**: Python-nmap wrapper for Nmap integration
- **Capabilities**:
  - TCP SYN scanning with service version detection
  - OS fingerprinting and banner grabbing
  - Configurable port ranges and scan intensity
- **Security**: Built-in rate limiting and target validation

#### 4. Vulnerability Assessment Module (`modules/vulnerability_scanner.py`)
- **Purpose**: Identifies vulnerabilities based on discovered services
- **Methods**:
  - CVE database matching via NVD API
  - Service-specific vulnerability checks
  - Web application security assessment
  - Technology stack vulnerability analysis
- **Features**: CVSS scoring, exploit availability tracking, patch status

#### 5. Risk Scoring Engine (`modules/risk_engine.py`)
- **Purpose**: Calculates comprehensive risk scores
- **Scoring Factors**:
  - Open ports and exposed services (25% weight)
  - Identified vulnerabilities (35% weight)
  - SSL/TLS configuration (20% weight)
  - Service configuration risks (20% weight)
- **Output**: 0-100 risk score with categorical classification

#### 6. Scanner Orchestrator (`modules/scanner_orchestrator.py`)
- **Purpose**: Coordinates the complete scanning workflow
- **Features**:
  - Concurrent scan management
  - Progress tracking and status reporting
  - Error handling and recovery
  - Result aggregation and analysis

### Data Models

The application uses Pydantic models for strong typing and validation:

```python
# Core entities
Lead: domain, company_name, timestamp
Asset: subdomain, ip_address, protocol, port, title, tech_stack
PortScanResult: ip_address, port, protocol, state, service, version
Vulnerability: cve_id, severity, cvss_score, description, affected_service
RiskScore: overall_score, risk_category, component_scores, recommendations

# Request/Response models
ScanRequest: leads, scan_type, options
ScanResult: scan_id, lead, assets, port_results, vulnerabilities, risk_score
APIResponse: message, data, status
```

### Risk Scoring Methodology

The risk scoring engine uses a weighted multi-factor approach:

#### Scoring Components

1. **Port Risk Score (25%)**
   - Base risk for any open port
   - Increased risk for high-risk services (FTP, Telnet, RDP)
   - Service-specific risk multipliers
   - Large attack surface penalties

2. **Vulnerability Risk Score (35%)**
   - CVSS base scores from CVE database
   - Severity-based multipliers (Critical: 4x, High: 3x, Medium: 2x, Low: 1x)
   - Exploit availability bonuses
   - Patch availability discounts

3. **SSL/TLS Risk Score (20%)**
   - Unencrypted HTTP penalties
   - Missing security headers assessment
   - HSTS implementation checks
   - Certificate configuration analysis

4. **Service Risk Score (20%)**
   - Administrative service exposure
   - Database service exposure
   - File service exposure
   - Outdated version detection

#### Risk Categories

- **Low (0-25)**: Minimal security concerns, standard precautions sufficient
- **Medium (26-50)**: Some security improvements recommended
- **High (51-75)**: Significant security concerns, prompt action needed
- **Critical (76-100)**: Immediate security review required

## 🔧 Configuration

### Environment Variables

```bash
# Application settings
APP_NAME="Cyber Insurance Scanner"
APP_VERSION="1.0.0"
DEBUG=false

# API configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=1

# Database settings (optional)
DATABASE_URL="postgresql://user:pass@localhost/scanner"
REDIS_URL="redis://localhost:6379/0"

# Security settings
SECRET_KEY="your-secret-key"
RATE_LIMIT_PER_MINUTE=60

# Scanning configuration
MAX_CONCURRENT_SCANS=5
NMAP_TIMEOUT=300
SUBDOMAIN_TIMEOUT=60
MAX_SUBDOMAINS_PER_DOMAIN=50

# External API configuration
CVE_API_URL="https://services.nvd.nist.gov/rest/json"

# Risk scoring weights (must sum to 1.0)
PORT_RISK_WEIGHT=0.25
VULNERABILITY_RISK_WEIGHT=0.35
SSL_RISK_WEIGHT=0.20
SERVICE_RISK_WEIGHT=0.20

# File paths
UPLOAD_DIR="./uploads"
REPORT_DIR="./reports"
LOG_DIR="./logs"
```

### Port Configuration

Customize port scanning behavior:

```python
# Default ports for quick scans
DEFAULT_PORT_LIST = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 6379]

# Common ports for standard scans  
COMMON_PORT_LIST = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

# High-risk ports with increased scoring
HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk": 3, "description": "Unencrypted file transfer"},
    23: {"service": "Telnet", "risk": 4, "description": "Unencrypted remote access"},
    135: {"service": "RPC", "risk": 3, "description": "Windows RPC endpoint"},
    445: {"service": "SMB", "risk": 3, "description": "Windows file sharing"},
    1433: {"service": "MSSQL", "risk": 3, "description": "Microsoft SQL Server"},
    3389: {"service": "RDP", "risk": 3, "description": "Windows Remote Desktop"},
    5900: {"service": "VNC", "risk": 3, "description": "Virtual Network Computing"}
}
```

## 📊 API Reference

### Core Endpoints

#### Lead Management
```http
POST /api/leads/upload
Content-Type: multipart/form-data

# Upload CSV/JSON/Excel file with leads
```

```http
POST /api/leads/validate
Content-Type: application/json

{
  "leads": [
    {"domain": "example.com", "company_name": "Example Corp"}
  ]
}
```

#### Scanning Operations
```http
POST /api/scan/quick
Content-Type: application/json

{
  "domain": "example.com",
  "company_name": "Example Corp"
}
```

```http
POST /api/scan/start
Content-Type: application/json

{
  "leads": [...],
  "scan_type": "full",
  "include_subdomains": true,
  "max_subdomains": 50,
  "port_scan_type": "common",
  "include_vulnerability_scan": true
}
```

#### Results and Analytics
```http
GET /api/results
GET /api/results/{scan_id}
GET /api/results/domain/{domain}

GET /api/analytics/summary
GET /api/analytics/executive-summary
GET /api/analytics/risk-distribution
```

#### Export Functions
```http
GET /api/export/csv/{scan_id}
GET /api/export/json/{scan_id}
```

### Response Formats

#### Scan Result Structure
```json
{
  "scan_id": "uuid-string",
  "lead": {
    "domain": "example.com",
    "company_name": "Example Corp",
    "timestamp": "2025-01-01T12:00:00Z"
  },
  "scan_status": "completed",
  "scan_started_at": "2025-01-01T12:00:00Z",
  "scan_completed_at": "2025-01-01T12:05:00Z",
  "scan_duration": 300.0,
  "assets": [...],
  "port_scan_results": [...],
  "vulnerabilities": [...],
  "risk_score": {
    "overall_score": 75.5,
    "risk_category": "high",
    "port_risk_score": 60.0,
    "vulnerability_risk_score": 85.0,
    "ssl_risk_score": 70.0,
    "service_risk_score": 80.0,
    "high_risk_ports": [21, 23, 3389],
    "critical_vulnerabilities": 2,
    "high_vulnerabilities": 5,
    "medium_vulnerabilities": 10,
    "low_vulnerabilities": 3,
    "total_assets": 15,
    "total_open_ports": 8,
    "total_vulnerabilities": 20
  }
}
```

## 🛠️ Development

### Project Structure
```
scanner/
├── config.py              # Configuration management
├── models.py               # Pydantic data models
├── api.py                  # FastAPI web application
├── cli.py                  # Command-line interface
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
├── modules/               # Core scanning modules
│   ├── __init__.py
│   ├── lead_input.py      # Lead processing
│   ├── asset_discovery.py # Asset discovery
│   ├── port_scanner.py    # Port scanning
│   ├── vulnerability_scanner.py # Vulnerability assessment
│   ├── risk_engine.py     # Risk scoring
│   └── scanner_orchestrator.py # Main orchestrator
├── uploads/               # File upload directory
├── reports/               # Generated reports
└── logs/                  # Application logs
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/

# Run with coverage
pytest --cov=modules tests/
```

### Development Setup

```bash
# Install in development mode
pip install -e .

# Run with auto-reload
python cli.py serve --reload

# Enable debug logging
python cli.py --verbose quick-scan example.com
```

## 🔒 Security Considerations

### Scanning Ethics
- **Rate Limiting**: Built-in delays to avoid overwhelming targets
- **Authorized Scanning**: Only scan domains you own or have permission to test
- **Network Courtesy**: Respectful scanning practices to avoid DoS
- **Legal Compliance**: Ensure compliance with local laws and regulations

### Data Protection
- **Sensitive Data**: Results may contain sensitive security information
- **Storage Security**: Encrypt results at rest in production
- **Access Control**: Implement authentication and authorization
- **Audit Logging**: Comprehensive logging of all scanning activities

### Deployment Security
- **API Security**: Use HTTPS in production
- **Input Validation**: All inputs are validated using Pydantic models
- **Error Handling**: Secure error responses without information disclosure
- **Resource Limits**: Configure appropriate timeouts and concurrency limits

## 🚢 Deployment

### Docker Deployment

```dockerfile
# Create Dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "api.py"]
```

```bash
# Build and run
docker build -t cyber-scanner .
docker run -p 8000:8000 cyber-scanner
```

### Production Deployment

```bash
# Use production WSGI server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker api:app

# Or use the built-in uvicorn with more workers
uvicorn api:app --host 0.0.0.0 --port 8000 --workers 4
```

### Environment Setup

```bash
# Production environment variables
export DEBUG=false
export DATABASE_URL="postgresql://user:pass@db:5432/scanner"
export REDIS_URL="redis://redis:6379/0"
export SECRET_KEY="your-production-secret-key"
export MAX_CONCURRENT_SCANS=10
```

## 📈 Usage Examples

### Example 1: Single Domain Scan

```bash
# Quick assessment of a domain
python cli.py quick-scan example.com --company "Example Corp" --output results.json

# View results
cat results.json | jq '.risk_score'
```

### Example 2: Batch Processing

Create `domains.csv`:
```csv
domain,company_name
example.com,Example Corp
test-site.org,Test Organization
demo.net,Demo Company
```

```bash
# Process batch file
python cli.py batch-scan domains.csv --output ./batch_results --scan-type full
```

### Example 3: API Integration

```python
import requests

# Start a scan via API
response = requests.post('http://localhost:8000/api/scan/quick', json={
    'domain': 'example.com',
    'company_name': 'Example Corp'
})

scan_result = response.json()
risk_score = scan_result['data']['risk_score']['overall_score']
print(f"Risk Score: {risk_score}")
```

### Example 4: Custom Risk Analysis

```python
from modules.scanner_orchestrator import ScannerOrchestrator
from modules.risk_engine import RiskScoringEngine

async def custom_analysis():
    scanner = ScannerOrchestrator()
    risk_engine = RiskScoringEngine()
    
    # Load previous scan results
    results = [...] # Load from storage
    
    # Generate executive summary
    summary = scanner.generate_executive_summary(results)
    
    # Custom risk recommendations
    for result in results:
        if result.risk_score.overall_score > 75:
            recommendations = risk_engine.generate_risk_recommendations(
                result.risk_score,
                result.vulnerabilities,
                result.port_scan_results
            )
            print(f"{result.lead.domain}: {recommendations}")
```

## 🤝 Contributing

### Contribution Guidelines

1. **Fork the repository** and create a feature branch
2. **Write tests** for new functionality
3. **Follow code style** conventions (PEP 8)
4. **Update documentation** for any API changes
5. **Submit a pull request** with clear description

### Code Style

```bash
# Install development tools
pip install black flake8 mypy

# Format code
black .

# Check style
flake8 .

# Type checking
mypy modules/
```

### Adding New Modules

To add a new scanning module:

1. Create module in `modules/` directory
2. Implement required interface methods
3. Add module to orchestrator workflow
4. Update configuration and models as needed
5. Add comprehensive tests
6. Update documentation

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🆘 Support & Troubleshooting

### Common Issues

**Nmap not found error:**
```bash
# Install Nmap
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

**Permission denied for port scanning:**
```bash
# Run with sudo if needed for raw socket access
sudo python cli.py full-scan example.com
```

**High memory usage during batch scans:**
```bash
# Reduce concurrent scans
python cli.py batch-scan domains.csv --max-concurrent 2
```

**Slow subdomain discovery:**
```bash
# Reduce subdomain limit
python cli.py full-scan example.com --max-subdomains 20
```

### Getting Help

- **Documentation**: Check this README and API docs at `/docs`
- **Issues**: Report bugs via GitHub issues
- **Discussions**: Use GitHub discussions for questions
- **Security Issues**: Report via email (see SECURITY.md)

### Performance Tuning

- **Concurrent Scans**: Adjust `MAX_CONCURRENT_SCANS` based on resources
- **Timeout Settings**: Tune `NMAP_TIMEOUT` and `SUBDOMAIN_TIMEOUT`
- **Resource Limits**: Monitor memory usage during large batch scans
- **Network Configuration**: Ensure adequate bandwidth for scanning

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Maintainer**: Cyber Insurance Tech Team 