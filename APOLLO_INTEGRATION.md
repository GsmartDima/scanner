# Apollo.io Integration for Cyber Insurance Scanner

## 🚀 Overview

The Apollo.io integration allows you to seamlessly import company data from Apollo.io exports and perform enriched bulk security scanning with business intelligence context.

## ✨ Key Features

### **1. Rich Data Import**
- **Automated parsing** of Apollo.io CSV exports
- **Business intelligence enrichment** with company metadata
- **Smart domain extraction** and validation
- **Priority-based scanning** using company data

### **2. Enhanced Scanning Context**
- **Company size analysis** (employee count, revenue)
- **Technology stack detection** from Apollo data
- **Industry-specific risk assessment** 
- **Geographic location context**

### **3. Parallel Processing**
- **4-16 simultaneous scans** (configurable)
- **Intelligent priority queuing** based on company data
- **Real-time progress tracking**
- **Automatic error recovery**

## 📊 Apollo Data Fields Supported

The scanner extracts and utilizes the following Apollo.io fields:

### **Required Fields**
- `Company` - Company name
- `Website` - Company website URL

### **Enrichment Fields**
- `# Employees` - Employee count for company size analysis
- `Industry` - Industry classification
- `Annual Revenue` - Revenue for risk profiling
- `Technologies` - Technology stack for security assessment
- `Short Description` - Company description
- `Founded Year` - Company age
- `Total Funding` - Investment funding
- `Company Phone` - Contact information
- `Company City/State/Country` - Geographic location

## 🎯 Priority Assignment Logic

The scanner automatically assigns scanning priority based on Apollo data:

### **High Priority** (🔴)
- Companies with **100+ employees**
- **$10M+ annual revenue**
- **10+ technologies** in tech stack
- **Cloud infrastructure** usage (AWS, Azure, Google Cloud)

### **Medium Priority** (🟡)
- **Default priority** for most companies
- Balanced risk profile

### **Low Priority** (🟢)
- **≤10 employees**
- **<$1M revenue**
- Limited technology presence

## 🔧 Usage Guide

### **Step 1: Export from Apollo.io**
1. In Apollo.io, select your target companies
2. Go to **Export → CSV Export**
3. Include all available fields
4. Download the CSV file

### **Step 2: Upload to Scanner**
1. Go to **http://localhost:8000**
2. Find the **Apollo.io Integration** section (blue header)
3. Click **Upload Apollo.io CSV Export**
4. Select your downloaded CSV file
5. Wait for processing (usually 5-10 seconds)

### **Step 3: Configure Scan**
- **Scan Type**: Quick (1-2 min/domain) or Full (2-4 min/domain)
- **Concurrency**: 4-16 parallel scans
  - Conservative (4): Safe for limited resources
  - Balanced (8): Recommended default
  - Aggressive (12): Fast scanning
  - Maximum (16): Fastest, requires good bandwidth

### **Step 4: Preview & Start**
1. Click **Preview Data** to review companies
2. Click **Start Apollo Bulk Scan**
3. Confirm scan parameters
4. Monitor progress in real-time

## 📈 Performance Metrics

### **Processing Speed**
- **Apollo CSV parsing**: ~50-100 companies/second
- **Domain extraction**: ~200 domains/second  
- **Parallel scanning**: 4-16 companies simultaneously

### **Typical Scan Times**
| Companies | Concurrency | Quick Scan | Full Scan |
|-----------|-------------|------------|-----------|
| 25        | 8 parallel | 3-6 min    | 6-12 min  |
| 50        | 8 parallel | 6-12 min   | 12-25 min |
| 100       | 16 parallel| 8-15 min   | 15-30 min |

## 🔍 Enhanced Scan Results

Apollo-enriched scans provide additional context:

### **Company Intelligence**
- Industry classification and risk factors
- Company size and maturity indicators  
- Technology stack and infrastructure
- Funding and growth stage
- Geographic presence

### **Risk Contextualization**
- Industry-specific vulnerability patterns
- Company size vs security posture correlation
- Technology stack security implications
- Geographic compliance requirements

## 🛠️ Technical Implementation

### **Backend Components**
- `modules/apollo_parser.py` - Apollo CSV parsing engine
- `/api/apollo/*` endpoints - REST API for Apollo operations
- Parallel processing with asyncio semaphores
- Enriched data storage with JSON metadata

### **Frontend Components**
- Apollo-specific UI section with enhanced styling
- Real-time upload progress and validation
- Company data preview with rich formatting
- Progress monitoring with detailed statistics

### **Data Flow**
1. **Upload** → Apollo CSV file via web interface
2. **Parse** → Extract and validate company data
3. **Enrich** → Add business intelligence metadata
4. **Queue** → Priority-based scan scheduling
5. **Execute** → Parallel security scanning
6. **Store** → Results with Apollo context
7. **Display** → Enhanced reporting with business context

## 🚨 Error Handling

### **Common Issues & Solutions**

**Invalid CSV Format**
- Ensure CSV has required headers: `Company`, `Website`
- Check for proper comma separation
- Verify UTF-8 encoding

**Domain Extraction Failures**
- Verify website URLs are properly formatted
- Remove http:// and www. prefixes in source data
- Check for typos in domain names

**Memory/Performance Issues**
- Reduce concurrency level for large datasets
- Process in smaller batches (<100 companies)
- Monitor system resources during scanning

## 📊 Example Apollo CSV Format

```csv
Company,Website,# Employees,Industry,Annual Revenue,Technologies
Example Corp,example.com,150,Technology,5000000,"AWS, React, PostgreSQL"
Test LLC,testsite.org,25,Healthcare,2000000,"Azure, Angular, MySQL"
Demo Inc,demo.net,500,Finance,50000000,"GCP, Vue.js, MongoDB"
```

## 🔮 Advanced Features

### **Retry Logic**
- Automatic retry for failed scans (2 attempts)
- Intelligent backoff strategies
- Error categorization and reporting

### **Progress Monitoring**
- Real-time scan status updates
- Completion percentage tracking  
- Success/failure rate monitoring
- Estimated time remaining

### **Data Persistence**
- Apollo data cached for re-scanning
- Enriched metadata stored with results
- Historical scan data retention

## 🎯 Best Practices

1. **Data Quality**: Clean Apollo exports before upload
2. **Batch Size**: Limit to 50-100 companies per scan
3. **Concurrency**: Start with balanced (8) setting
4. **Monitoring**: Watch progress and adjust as needed
5. **Resources**: Ensure adequate bandwidth and memory

## 🔒 Security Considerations

- Apollo data processed locally (not stored externally)
- Temporary files cleaned up automatically
- Secure domain validation and sanitization
- Rate limiting to prevent service overload

## 📞 Support

For issues with Apollo integration:
1. Check server logs: `logs/scanner.log`
2. Verify CSV format and data quality
3. Test with smaller datasets first
4. Monitor system resources during scanning

---

**Apollo.io Integration** - Bringing business intelligence to cybersecurity scanning! 🚀🔒 