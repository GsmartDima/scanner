"""
FastAPI Application for Cyber Insurance Scanner
Provides REST API endpoints for all scanning functionality
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import os
import sys
import uuid
import re
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pydantic import BaseModel, ValidationError

from config import settings
from models import (
    Lead, ScanRequest, ScanResult, APIResponse, FileUploadResponse,
    ScanSummary, DomainSummary
)
from modules.lead_input import LeadInputProcessor
from modules.scanner_orchestrator import ScannerOrchestrator
from modules.security_utils import (
    escape_html, escape_html_attribute, sanitize_html_content,
    create_safe_html_snippet, validate_cve_id, validate_severity_level,
    sanitize_port_number, sanitize_ip_address, create_vulnerability_badge_html,
    group_vulnerabilities_by_severity, get_open_ports, count_vulnerabilities_by_severity,
    calculate_risk_metrics
)
try:
    from modules.ml_exploit_prediction import MLExploitPredictor, SalesIntelligenceGenerator
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
from modules.apollo_parser import parse_apollo_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Path(settings.log_dir) / 'scanner.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="Cyber Insurance Scanner API for automated security assessments",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (uploads removed for security - use protected endpoint instead)
app.mount("/static", StaticFiles(directory="static"), name="static")
# SECURITY: Removed public uploads mount - files now served via protected endpoint

# Initialize components
lead_processor = LeadInputProcessor()
scanner_orchestrator = ScannerOrchestrator()

# Store scan results (in production, use database)
scan_results_store: Dict[str, ScanResult] = {}
scan_status: Dict[str, str] = {}

class QuickScanRequest(BaseModel):
    domain: str
    company_name: str = "Unknown"

class FullScanRequest(BaseModel):
    domain: str
    company_name: str = "Unknown"
    scan_options: Optional[Dict[str, Any]] = None


# Security functions
def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key")) -> str:
    """Verify API key for protected endpoints"""
    if settings.require_auth and (not x_api_key or x_api_key != settings.api_key):
        logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
        raise HTTPException(
            status_code=401, 
            detail="Invalid or missing API key. Include X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return x_api_key


@app.get("/api/files/{file_id}")
async def get_protected_file(file_id: str, api_key: str = Depends(verify_api_key)):
    """Serve uploaded files with access control"""
    try:
        # Validate file_id format (UUID + filename pattern)
        if not re.match(r'^[a-f0-9]{32}_[a-zA-Z0-9._-]+$', file_id):
            logger.warning(f"Invalid file ID format requested: {file_id}")
            raise HTTPException(status_code=400, detail="Invalid file ID format")
        
        file_path = Path(settings.upload_dir) / file_id
        
        # Validate path is within uploads directory (additional path traversal protection)
        upload_dir_resolved = Path(settings.upload_dir).resolve()
        file_path_resolved = file_path.resolve()
        
        if not str(file_path_resolved).startswith(str(upload_dir_resolved)):
            logger.error(f"Path traversal attempt detected: {file_path_resolved}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not file_path.exists():
            logger.warning(f"File not found: {file_id}")
            raise HTTPException(status_code=404, detail="File not found")
        
        logger.info(f"Serving protected file: {file_id}")
        return FileResponse(
            path=file_path,
            filename=file_id.split('_', 1)[-1],  # Original filename after UUID
            media_type='application/octet-stream'
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving protected file {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Create necessary directories
    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.report_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.log_dir).mkdir(parents=True, exist_ok=True)
    
    logger.info("Application startup completed")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    logger.info("Application shutting down")


# Health check endpoint
@app.get("/health", response_model=APIResponse)
async def health_check():
    """Health check endpoint"""
    return APIResponse(
        message="Service is healthy",
        data={
            "service": settings.app_name,
            "version": settings.app_version,
            "status": "running"
        }
    )

@app.get("/test-clear")
async def test_clear():
    """Test endpoint to verify server is loading updated code"""
    return {"message": "Test endpoint working", "timestamp": datetime.now().isoformat()}


# Lead management endpoints
@app.post("/api/leads/upload", response_model=APIResponse)
async def upload_leads_file(file: UploadFile = File(...), api_key: str = Depends(verify_api_key)):
    """Upload and process leads from CSV/JSON/Excel file"""
    try:
        upload_response, valid_leads = await lead_processor.process_file_upload(file)
        
        return APIResponse(
            message=f"File processed successfully: {upload_response.valid_leads} valid leads",
            data={
                "upload_details": upload_response.dict(),
                "leads": [lead.dict() for lead in valid_leads]
            }
        )
    
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/leads/validate", response_model=APIResponse)
async def validate_leads(leads: List[Lead]):
    """Validate a list of leads"""
    try:
        # Remove duplicates
        unique_leads = lead_processor.remove_duplicates(leads)
        
        return APIResponse(
            message=f"Validated {len(unique_leads)} unique leads",
            data={
                "original_count": len(leads),
                "unique_count": len(unique_leads),
                "duplicates_removed": len(leads) - len(unique_leads),
                "leads": [lead.dict() for lead in unique_leads]
            }
        )
    
    except Exception as e:
        logger.error(f"Lead validation failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


# Scanning endpoints
@app.post("/api/scan/start", response_model=APIResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """Start a new security scan"""
    try:
        # Validate leads
        unique_leads = lead_processor.remove_duplicates(scan_request.leads)
        scan_request.leads = unique_leads
        
        # Start scan in background
        background_tasks.add_task(execute_scan_background, scan_request)
        
        return APIResponse(
            message=f"Scan started for {len(unique_leads)} domains",
            data={
                "leads_count": len(unique_leads),
                "scan_type": scan_request.scan_type,
                "estimated_duration_minutes": len(unique_leads) * 2  # Rough estimate
            }
        )
    
    except Exception as e:
        logger.error(f"Scan start failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


async def execute_scan_background(scan_request: ScanRequest):
    """Execute scan in background and store results"""
    try:
        results = await scanner_orchestrator.execute_scan(scan_request)
        
        # Store results
        for result in results:
            scan_results_store[result.scan_id] = result
        
        logger.info(f"Background scan completed: {len(results)} results")
        
    except Exception as e:
        logger.error(f"Background scan failed: {str(e)}")


@app.post("/api/scan/quick", response_model=APIResponse)
async def quick_scan(request: QuickScanRequest, api_key: str = Depends(verify_api_key)):
    """Perform a quick scan on a single domain"""
    try:
        # Create Lead object from request
        lead = Lead(
            domain=request.domain,
            company_name=request.company_name,
            email="",
            contact_person=""
        )
        
        result = await scanner_orchestrator.quick_scan(lead)
        
        if result:
            scan_results_store[result.scan_id] = result
            
            return APIResponse(
                message=f"Quick scan completed for {request.domain}",
                data={
                    **result.dict(),
                    "progress_url": f"/scan/{result.scan_id}"
                }
            )
        else:
            raise HTTPException(status_code=500, detail="Scan failed")
    
    except Exception as e:
        logger.error(f"Quick scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/full", response_model=APIResponse)
async def full_scan(request: FullScanRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """Perform a comprehensive full scan on a single domain"""
    try:
        # Create Lead object from request
        lead = Lead(
            domain=request.domain,
            company_name=request.company_name,
            email="",
            contact_person=""
        )
        
        # Generate scan ID upfront for tracking
        scan_id = str(uuid.uuid4())
        
        # Start full scan in background with scan ID
        background_tasks.add_task(execute_full_scan_background, lead, scan_id)
        
        return APIResponse(
            message=f"Full scan started for {request.domain}",
            data={
                "scan_id": scan_id,
                "domain": request.domain,
                "company_name": request.company_name,
                "scan_type": "full",
                "estimated_duration_minutes": 5,
                "status": "started",
                "progress_url": f"/scan/{scan_id}"
            }
        )
    
    except Exception as e:
        logger.error(f"Full scan start failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


async def execute_full_scan_background(lead: Lead, scan_id: str = None):
    """Execute full scan in background with predefined scan ID"""
    try:
        # Use provided scan ID or generate new one
        if scan_id:
            # Manually set scan ID in the scanner orchestrator
            result = await scanner_orchestrator.full_scan_with_id(lead, scan_id)
        else:
            result = await scanner_orchestrator.full_scan(lead)
            
        if result:
            scan_results_store[result.scan_id] = result
        logger.info(f"Full scan completed for {lead.domain}")
    except Exception as e:
        logger.error(f"Full scan failed for {lead.domain}: {str(e)}")


@app.get("/api/scan/status", response_model=APIResponse)
async def get_scan_status():
    """Get status of all active scans"""
    try:
        active_scans = scanner_orchestrator.get_active_scans()
        
        return APIResponse(
            message=f"Found {len(active_scans)} active scans",
            data={"active_scans": active_scans}
        )
    
    except Exception as e:
        logger.error(f"Get scan status failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/progress", response_model=APIResponse)
async def get_all_scan_progress():
    """Get real-time progress for all active scans"""
    try:
        all_progress = scanner_orchestrator.get_all_scan_progress()
        
        return APIResponse(
            message=f"Retrieved progress for {len(all_progress)} scans",
            data={"scans": all_progress}
        )
    
    except Exception as e:
        logger.error(f"Get scan progress failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/progress/{scan_id}", response_model=APIResponse)
async def get_scan_progress(scan_id: str):
    """Get real-time progress for a specific scan"""
    try:
        progress = scanner_orchestrator.get_scan_progress(scan_id)
        
        if progress:
            return APIResponse(
                message=f"Progress retrieved for scan {scan_id}",
                data=progress
            )
        else:
            # Check if scan exists in completed results
            if scan_id in scan_results_store:
                scan_result = scan_results_store[scan_id]
                return APIResponse(
                    message=f"Scan {scan_id} completed",
                    data={
                        'scan_id': scan_id,
                        'status': 'completed',
                        'overall_progress': 100,
                        'lead': {
                            'domain': scan_result.lead.domain,
                            'company_name': scan_result.lead.company_name
                        },
                        'completed_at': scan_result.scan_completed_at.isoformat() if scan_result.scan_completed_at else None,
                        'risk_score': scan_result.risk_score.dict() if scan_result.risk_score else None
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="Scan not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get scan progress failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}/logs", response_model=APIResponse)
async def get_scan_logs(scan_id: str, last: int = 100):
    """Get real-time logs for a specific scan"""
    try:
        # Get the ScanProgress object directly from the orchestrator
        scan_progress_obj = scanner_orchestrator.scan_progress.get(scan_id)
        
        if scan_progress_obj:
            # Get logs from the ScanProgress object
            all_logs = scan_progress_obj.logs
            logs = all_logs[-last:] if last > 0 and len(all_logs) > last else all_logs
            
            return APIResponse(
                message=f"Retrieved {len(logs)} log entries for scan {scan_id}",
                data={
                    'scan_id': scan_id,
                    'logs': logs,
                    'status': scan_progress_obj.status,
                    'total_logs': len(all_logs),
                    'current_phase': scan_progress_obj.current_phase.value
                }
            )
        else:
            # Check if scan is completed and has no active progress
            if scan_id in scan_results_store:
                return APIResponse(
                    message=f"Scan {scan_id} is completed - no active logs available",
                    data={
                        'scan_id': scan_id,
                        'logs': [
                            {
                                'timestamp': datetime.now().isoformat(),
                                'level': 'info',
                                'message': 'Scan completed. No active logs available.',
                                'phase': 'completed'
                            }
                        ],
                        'status': 'completed',
                        'total_logs': 1,
                        'current_phase': 'completed'
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="Scan not found or logs not available")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get scan logs failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans/all", response_model=APIResponse)
async def get_all_scans():
    """Get all scans (both active and completed) with their status"""
    try:
        all_scans = []
        
        # Get active scans with progress
        active_progress = scanner_orchestrator.get_all_scan_progress()
        active_progress_dict = {}
        
        for progress in active_progress:
            scan_id = progress.get('scan_id')
            if scan_id:
                active_progress_dict[scan_id] = progress
        
        for scan_id, progress in active_progress_dict.items():
            all_scans.append({
                'scan_id': scan_id,
                'domain': progress.get('lead', {}).get('domain', 'Unknown'),
                'company_name': progress.get('lead', {}).get('company_name', 'Unknown'),
                'status': progress.get('status', 'unknown'),
                'overall_progress': progress.get('overall_progress', 0),
                'current_phase': progress.get('current_phase', 'Unknown'),
                'started_at': progress.get('started_at'),
                'completed_at': None,
                'risk_score': None,
                'scan_type': 'active'
            })
        
        # Get completed scans
        for scan_id, scan_result in scan_results_store.items():
            # Skip if already in active scans
            if scan_id in active_progress_dict:
                continue
                
            risk_level = 'unknown'
            if scan_result.risk_score:
                risk_level = scan_result.risk_score.risk_level.lower()
            
            all_scans.append({
                'scan_id': scan_id,
                'domain': scan_result.lead.domain,
                'company_name': scan_result.lead.company_name,
                'status': 'completed',
                'overall_progress': 100,
                'current_phase': 'Completed',
                'started_at': scan_result.scan_started_at.isoformat() if scan_result.scan_started_at else None,
                'completed_at': scan_result.scan_completed_at.isoformat() if scan_result.scan_completed_at else None,
                'risk_score': scan_result.risk_score.dict() if scan_result.risk_score else None,
                'risk_level': risk_level,
                'scan_type': 'completed'
            })
        
        # Sort by start time (most recent first), handle None values
        all_scans.sort(key=lambda x: x.get('started_at') or '', reverse=True)
        
        return APIResponse(
            message=f"Retrieved {len(all_scans)} scans ({len(active_progress_dict)} active, {len(scan_results_store) - len(active_progress_dict)} completed)",
            data={"scans": all_scans}
        )
    
    except Exception as e:
        logger.error(f"Get all scans failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}")
async def scan_detail_page(scan_id: str, request: Request):
    """Individual scan detail page"""
    try:
        # Check if scan exists (either in progress or completed)
        progress = scanner_orchestrator.get_scan_progress(scan_id)
        scan_result = scan_results_store.get(scan_id)
        
        if not progress and not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return templates.TemplateResponse("scan_detail.html", {
            "request": request,
            "scan_id": scan_id
        })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan detail page failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}/detailed", response_model=APIResponse)
async def get_scan_detailed_info(scan_id: str):
    """Get comprehensive information about a scan including progress and results"""
    try:
        # Get progress (for running scans)
        progress = scanner_orchestrator.get_scan_progress(scan_id)
        
        # Get results (for completed scans)
        scan_result = scan_results_store.get(scan_id)
        
        if not progress and not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        response_data = {}
        
        # Add progress information
        if progress:
            response_data['progress'] = progress
        
        # Add scan results if available
        if scan_result:
            response_data['results'] = scan_result.dict()
            
            # Debug log for vulnerability data
            logger.info(f"Scan {scan_id}: Returning {len(scan_result.vulnerabilities)} vulnerabilities")
            if scan_result.vulnerabilities:
                logger.info(f"First vulnerability: {scan_result.vulnerabilities[0].cve_id}")
        
        # Add scan status
        if progress:
            response_data['status'] = progress['status']
        elif scan_result:
            response_data['status'] = scan_result.scan_status
        
        return APIResponse(
            message=f"Retrieved detailed information for scan {scan_id}",
            data=response_data
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get detailed scan info failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/status/{scan_id}", response_model=APIResponse)
async def get_specific_scan_status(scan_id: str):
    """Get status of a specific scan"""
    try:
        # First check if scan is running
        progress = scanner_orchestrator.get_scan_progress(scan_id)
        if progress:
            return APIResponse(
                message=f"Scan {scan_id} is running",
                data={
                    "scan_id": scan_id,
                    "status": "running",
                    "progress": progress['overall_progress'],
                    "current_phase": progress['current_phase']
                }
            )
        
        # Check if scan is completed
        if scan_id in scan_results_store:
            scan_result = scan_results_store[scan_id]
            return APIResponse(
                message=f"Scan {scan_id} completed",
                data={
                    "scan_id": scan_id,
                    "status": scan_result.scan_status,
                    "domain": scan_result.lead.domain,
                    "completed_at": scan_result.scan_completed_at.isoformat() if scan_result.scan_completed_at else None,
                    "risk_score": scan_result.risk_score.overall_score if scan_result.risk_score else None
                }
            )
        
        raise HTTPException(status_code=404, detail="Scan not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get specific scan status failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/scan/{scan_id}", response_model=APIResponse)
async def cancel_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Cancel a running scan"""
    try:
        cancelled = scanner_orchestrator.cancel_scan(scan_id)
        
        if cancelled:
            return APIResponse(
                message=f"Scan {scan_id} cancelled successfully",
                data={"scan_id": scan_id, "status": "cancelled"}
            )
        else:
            raise HTTPException(status_code=404, detail="Scan not found or already completed")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cancel scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scans/clear-all", response_model=APIResponse)
async def clear_all_scans(api_key: str = Depends(verify_api_key)):
    """Clear all scans and results"""
    try:
        # Cancel all active scans
        cancelled_count = 0
        active_scan_ids = list(scanner_orchestrator.active_scans.keys())
        for scan_id in active_scan_ids:
            if scanner_orchestrator.cancel_scan(scan_id):
                cancelled_count += 1
        
        # Clear scan progress tracking
        scanner_orchestrator.scan_progress.clear()
        
        # Clear all scan results
        results_count = len(scan_results_store)
        scan_results_store.clear()
        
        return APIResponse(
            message=f"Cleared {cancelled_count} active scans and {results_count} stored results",
            data={
                'cancelled_scans': cancelled_count,
                'cleared_results': results_count,
                'total_cleared': cancelled_count + results_count
            }
        )
    
    except Exception as e:
        logger.error(f"Clear all scans failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to clear scans: {str(e)}")


# Results endpoints
@app.get("/api/results", response_model=APIResponse)
async def get_all_results():
    """Get all scan results"""
    try:
        results = list(scan_results_store.values())
        
        return APIResponse(
            message=f"Retrieved {len(results)} scan results",
            data={
                "total_results": len(results),
                "results": [result.dict() for result in results]
            }
        )
    
    except Exception as e:
        logger.error(f"Get all results failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/results/{scan_id}", response_model=APIResponse)
async def get_scan_result(scan_id: str):
    """Get specific scan result"""
    try:
        if scan_id in scan_results_store:
            result = scan_results_store[scan_id]
            return APIResponse(
                message="Scan result retrieved",
                data=result.dict()
            )
        else:
            raise HTTPException(status_code=404, detail="Scan result not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get scan result failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/results/domain/{domain}", response_model=APIResponse)
async def get_domain_results(domain: str):
    """Get all scan results for a specific domain"""
    try:
        domain_results = [
            result for result in scan_results_store.values()
            if result.lead.domain == domain
        ]
        
        return APIResponse(
            message=f"Found {len(domain_results)} results for {domain}",
            data={
                "domain": domain,
                "results_count": len(domain_results),
                "results": [result.dict() for result in domain_results]
            }
        )
    
    except Exception as e:
        logger.error(f"Get domain results failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Apollo.io Integration Endpoints
@app.post("/api/apollo/upload", response_model=APIResponse)
async def upload_apollo_csv(file: UploadFile = File(...), api_key: str = Depends(verify_api_key)):
    """Upload and parse Apollo.io CSV export file"""
    try:
        # Validate file type
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="File must be a CSV file")
        
        # Save uploaded file temporarily
        temp_file_path = Path(settings.upload_dir) / f"apollo_temp_{uuid.uuid4().hex}.csv"
        
        with open(temp_file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Parse Apollo CSV
        parse_results = parse_apollo_file(
            str(temp_file_path),
            output_csv=str(Path(settings.upload_dir) / "apollo_scanner_format.csv"),
            output_json=str(Path(settings.upload_dir) / "apollo_enriched_data.json")
        )
        
        # Clean up temp file
        temp_file_path.unlink()
        
        if not parse_results['success']:
            raise HTTPException(status_code=400, detail="Failed to parse Apollo CSV file")
        
        return APIResponse(
            message=f"Apollo CSV processed successfully: {parse_results['stats']['valid_companies']} companies ready for scanning",
            data={
                "parsing_stats": parse_results['stats'],
                "companies": parse_results['data'][:10],  # Preview first 10 companies
                "total_companies": len(parse_results['data']),
                "errors": parse_results['errors']
            }
        )
    
    except Exception as e:
        logger.error(f"Apollo CSV upload failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/apollo/bulk-scan", response_model=APIResponse)
async def start_apollo_bulk_scan(
    scan_type: str = "full",
    concurrency: int = 8,
    background_tasks: BackgroundTasks = None,
    api_key: str = Depends(verify_api_key)
):
    """Start bulk scanning of previously uploaded Apollo companies"""
    try:
        # Check if Apollo data exists
        apollo_csv_path = Path(settings.upload_dir) / "apollo_scanner_format.csv"
        apollo_json_path = Path(settings.upload_dir) / "apollo_enriched_data.json"
        
        if not apollo_csv_path.exists():
            raise HTTPException(status_code=400, detail="No Apollo data found. Please upload Apollo CSV first.")
        
        # Load Apollo data
        with open(apollo_json_path, 'r') as f:
            apollo_data = json.load(f)
        
        companies = apollo_data['companies']
        
        # Start bulk scanning in background
        background_tasks.add_task(
            execute_apollo_bulk_scan_background, 
            companies, 
            scan_type, 
            concurrency
        )
        
        return APIResponse(
            message=f"Apollo bulk scan started for {len(companies)} companies",
            data={
                "total_companies": len(companies),
                "scan_type": scan_type,
                "concurrency": concurrency,
                "estimated_duration_minutes": (len(companies) * 3) // concurrency
            }
        )
    
    except Exception as e:
        logger.error(f"Apollo bulk scan failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


async def execute_apollo_bulk_scan_background(companies: List[Dict], scan_type: str, concurrency: int):
    """Execute Apollo bulk scan in background with parallel processing"""
    try:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def scan_company(company_data: Dict):
            async with semaphore:
                try:
                    # Create lead from Apollo data
                    lead = Lead(
                        domain=company_data['domain'],
                        company_name=company_data['company_name'],
                        contact_email=company_data.get('contact_email', ''),
                        priority=company_data.get('priority', 'medium')
                    )
                    
                    # Execute scan
                    scan_id = str(uuid.uuid4())
                    scan_status[scan_id] = "running"
                    
                    if scan_type == "quick":
                        result = await scanner_orchestrator.quick_scan_with_id(lead, scan_id)
                    else:
                        result = await scanner_orchestrator.full_scan_with_id(lead, scan_id)
                    
                    # Enrich result with Apollo data
                    if hasattr(result, 'apollo_data'):
                        result.apollo_data = company_data.get('apollo_data', {})
                    
                    # Store result
                    scan_results_store[scan_id] = result
                    scan_status[scan_id] = "completed"
                    
                    logger.info(f"Apollo scan completed for {company_data['company_name']} -> {company_data['domain']}")
                    
                except Exception as e:
                    logger.error(f"Apollo scan failed for {company_data.get('domain', 'unknown')}: {str(e)}")
                    if 'scan_id' in locals():
                        scan_status[scan_id] = "failed"
        
        # Execute all scans with controlled concurrency
        tasks = [scan_company(company) for company in companies]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Apollo bulk scan completed: {len(companies)} companies processed")
        
    except Exception as e:
        logger.error(f"Apollo bulk scan background execution failed: {str(e)}")


@app.get("/api/apollo/scanner-data", response_model=APIResponse)
async def get_apollo_scanner_data():
    """Get Apollo scanner format data for bulk scanning"""
    try:
        apollo_json_path = Path(settings.upload_dir) / "apollo_enriched_data.json"
        
        if not apollo_json_path.exists():
            raise HTTPException(status_code=404, detail="No Apollo data found. Please upload Apollo CSV first.")
        
        # Load Apollo data
        with open(apollo_json_path, 'r') as f:
            apollo_data = json.load(f)
        
        # Convert to scanner format
        scanner_data = []
        for company in apollo_data['companies']:
            scanner_data.append({
                'domain': company['domain'],
                'company_name': company['company_name'],
                'contact_email': company.get('contact_email', ''),
                'priority': company.get('priority', 'medium')
            })
        
        return APIResponse(
            message=f"Apollo scanner data retrieved: {len(scanner_data)} companies",
            data={
                "companies": scanner_data,
                "total_count": len(scanner_data)
            }
        )
    
    except Exception as e:
        logger.error(f"Apollo scanner data retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/apollo/status", response_model=APIResponse)
async def get_apollo_status():
    """Get status of Apollo data and bulk scanning"""
    try:
        apollo_csv_path = Path(settings.upload_dir) / "apollo_scanner_format.csv"
        apollo_json_path = Path(settings.upload_dir) / "apollo_enriched_data.json"
        
        apollo_available = apollo_csv_path.exists() and apollo_json_path.exists()
        company_count = 0
        
        if apollo_available:
            with open(apollo_json_path, 'r') as f:
                apollo_data = json.load(f)
                company_count = len(apollo_data['companies'])
        
        # Count Apollo-related scans (simplified check)
        total_scans = len(scan_status)
        
        return APIResponse(
            message="Apollo status retrieved",
            data={
                "apollo_data_available": apollo_available,
                "total_companies": company_count,
                "total_scans": total_scans
            }
        )
    
    except Exception as e:
        logger.error(f"Apollo status check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Analytics and reporting endpoints
@app.get("/api/analytics/summary", response_model=APIResponse)
async def get_scan_summary():
    """Get summary analytics of all scans"""
    try:
        results = list(scan_results_store.values())
        analysis = scanner_orchestrator.analyze_scan_results(results)
        
        return APIResponse(
            message="Scan summary generated",
            data=analysis
        )
    
    except Exception as e:
        logger.error(f"Get scan summary failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/executive-summary", response_model=APIResponse)
async def get_executive_summary():
    """Get executive summary of all scans"""
    try:
        results = list(scan_results_store.values())
        summary = scanner_orchestrator.generate_executive_summary(results)
        
        return APIResponse(
            message="Executive summary generated",
            data=summary
        )
    
    except Exception as e:
        logger.error(f"Get executive summary failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/risk-distribution", response_model=APIResponse)
async def get_risk_distribution():
    """Get risk distribution across all scanned domains"""
    try:
        results = list(scan_results_store.values())
        completed_results = [r for r in results if r.scan_status == "completed" and r.risk_score]
        
        risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        domain_scores = []
        
        for result in completed_results:
            category = result.risk_score.risk_category
            if category in risk_dist:
                risk_dist[category] += 1
            
            domain_scores.append({
                "domain": result.lead.domain,
                "score": result.risk_score.overall_score,
                "category": result.risk_score.risk_category
            })
        
        # Sort by score
        domain_scores.sort(key=lambda x: x["score"], reverse=True)
        
        return APIResponse(
            message="Risk distribution calculated",
            data={
                "total_domains": len(completed_results),
                "risk_distribution": risk_dist,
                "high_risk_domains": [d for d in domain_scores if d["score"] >= 75][:10],
                "all_domains": domain_scores
            }
        )
    
    except Exception as e:
        logger.error(f"Get risk distribution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/domain-summary", response_model=APIResponse)
async def get_domain_summary():
    """Get comprehensive domain summary showing clean vs vulnerable domains"""
    try:
        results = list(scan_results_store.values())
        completed_results = [r for r in results if r.scan_status == "completed"]
        
        if not completed_results:
            return APIResponse(
                message="No completed scans found",
                data=DomainSummary().dict()
            )
        
        # Initialize counters
        clean_domains = []
        vulnerable_domains = []
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_vulnerabilities = 0
        
        # Process each domain
        for result in completed_results:
            domain = result.lead.domain
            company_name = result.lead.company_name
            vuln_count = len(result.vulnerabilities)
            
            # Count vulnerabilities by severity
            domain_severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for vuln in result.vulnerabilities:
                if vuln.severity in domain_severity_count:
                    domain_severity_count[vuln.severity] += 1
                    severity_breakdown[vuln.severity] += 1
            
            total_vulnerabilities += vuln_count
            
            # Domain info
            domain_info = {
                "domain": domain,
                "company_name": company_name,
                "scan_id": result.scan_id,
                "scan_completed_at": result.scan_completed_at.isoformat() if result.scan_completed_at else None,
                "vulnerability_count": vuln_count,
                "severity_breakdown": domain_severity_count,
                "risk_score": result.risk_score.overall_score if result.risk_score else 0,
                "risk_category": result.risk_score.risk_category if result.risk_score else "unknown"
            }
            
            # Categorize as clean or vulnerable
            if vuln_count == 0:
                clean_domains.append(domain_info)
            else:
                vulnerable_domains.append(domain_info)
        
        # Sort vulnerable domains by vulnerability count (descending)
        vulnerable_domains.sort(key=lambda x: x["vulnerability_count"], reverse=True)
        
        # Sort clean domains by domain name
        clean_domains.sort(key=lambda x: x["domain"])
        
        # Find highest and lowest risk domains
        highest_risk_domain = None
        lowest_risk_domain = None
        
        if completed_results:
            # Find domains with risk scores
            domains_with_risk = [r for r in completed_results if r.risk_score]
            if domains_with_risk:
                highest_risk = max(domains_with_risk, key=lambda x: x.risk_score.overall_score)
                lowest_risk = min(domains_with_risk, key=lambda x: x.risk_score.overall_score)
                
                highest_risk_domain = {
                    "domain": highest_risk.lead.domain,
                    "company_name": highest_risk.lead.company_name,
                    "risk_score": highest_risk.risk_score.overall_score,
                    "risk_category": highest_risk.risk_score.risk_category,
                    "vulnerability_count": len(highest_risk.vulnerabilities)
                }
                
                lowest_risk_domain = {
                    "domain": lowest_risk.lead.domain,
                    "company_name": lowest_risk.lead.company_name,
                    "risk_score": lowest_risk.risk_score.overall_score,
                    "risk_category": lowest_risk.risk_score.risk_category,
                    "vulnerability_count": len(lowest_risk.vulnerabilities)
                }
        
        # Calculate average vulnerabilities per domain
        avg_vulnerabilities = total_vulnerabilities / len(completed_results) if completed_results else 0
        
        # Create summary
        summary = DomainSummary(
            total_domains=len(completed_results),
            clean_domains=len(clean_domains),
            vulnerable_domains=len(vulnerable_domains),
            clean_domain_list=clean_domains,
            vulnerable_domain_list=vulnerable_domains,
            total_vulnerabilities=total_vulnerabilities,
            severity_breakdown=severity_breakdown,
            highest_risk_domain=highest_risk_domain,
            lowest_risk_domain=lowest_risk_domain,
            average_vulnerabilities_per_domain=round(avg_vulnerabilities, 2)
        )
        
        return APIResponse(
            message=f"Domain summary generated for {len(completed_results)} domains",
            data=summary.dict()
        )
    
    except Exception as e:
        logger.error(f"Get domain summary failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Export endpoints
@app.get("/api/export/csv/{scan_id}")
async def export_scan_csv(scan_id: str):
    """Export scan result as CSV"""
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Scan result not found")
        
        result = scan_results_store[scan_id]
        
        # Generate CSV content
        csv_content = generate_scan_csv(result)
        
        # Save to file
        filename = f"scan_{scan_id}_{result.lead.domain}.csv"
        file_path = Path(settings.report_dir) / filename
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            f.write(csv_content)
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='text/csv'
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export CSV failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export/json/{scan_id}")
async def export_scan_json(scan_id: str):
    """Export scan result as JSON"""
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Scan result not found")
        
        result = scan_results_store[scan_id]
        
        # Save to file
        filename = f"scan_{scan_id}_{result.lead.domain}.json"
        file_path = Path(settings.report_dir) / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(result.dict(), f, indent=2, default=str)
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/json'
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export JSON failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export/html/{scan_id}")
async def export_scan_html(scan_id: str):
    """Download the generated HTML threat analysis report"""
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Scan result not found")
        
        result = scan_results_store[scan_id]
        
        # Check if HTML was generated during scan
        if hasattr(result, 'html_report_path') and result.html_report_path and Path(result.html_report_path).exists():
            html_path = Path(result.html_report_path)
            filename = f"threat_analysis_{result.lead.domain}_{datetime.now().strftime('%Y%m%d')}.html"
            
            logger.info(f"Serving HTML report for scan {scan_id}: {html_path}")
            return FileResponse(
                path=html_path,
                filename=filename,
                media_type='text/html'
            )
        else:
            # Try to generate HTML on-demand if not available
            try:
                from modules.pdf_generator import PDFReportGenerator
                html_generator = PDFReportGenerator()
                
                html_scan_data = result.dict()
                html_path = html_generator.generate_html_report(html_scan_data, scan_id)
                
                if html_path and Path(html_path).exists():
                    # Update scan result with HTML path
                    if not hasattr(result, 'html_report_path'):
                        # Add the field if it doesn't exist
                        result.html_report_path = html_path
                    else:
                        result.html_report_path = html_path
                    scan_results_store[scan_id] = result
                    
                    filename = f"threat_analysis_{result.lead.domain}_{datetime.now().strftime('%Y%m%d')}.html"
                    
                    logger.info(f"Generated HTML on-demand for scan {scan_id}: {html_path}")
                    return FileResponse(
                        path=html_path,
                        filename=filename,
                        media_type='text/html'
                    )
                else:
                    raise HTTPException(status_code=500, detail="Failed to generate HTML report")
                    
            except Exception as html_error:
                logger.error(f"On-demand HTML generation failed for {scan_id}: {html_error}")
                raise HTTPException(status_code=500, detail="HTML report not available and generation failed")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export HTML failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export/pdf/{scan_id}")
async def export_scan_pdf(scan_id: str):
    """Download the generated PDF threat analysis report"""
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Scan result not found")
        
        result = scan_results_store[scan_id]
        
        # Check if PDF was generated during scan
        if result.pdf_report_path and Path(result.pdf_report_path).exists():
            pdf_path = Path(result.pdf_report_path)
            filename = f"threat_analysis_{result.lead.domain}_{datetime.now().strftime('%Y%m%d')}.pdf"
            
            logger.info(f"Serving PDF report for scan {scan_id}: {pdf_path}")
            return FileResponse(
                path=pdf_path,
                filename=filename,
                media_type='application/pdf'
            )
        else:
            # Try to generate PDF on-demand if not available
            try:
                from modules.pdf_generator import PDFReportGenerator
                pdf_generator = PDFReportGenerator()
                
                pdf_scan_data = result.dict()
                pdf_path = pdf_generator.generate_threat_analysis_pdf(pdf_scan_data, scan_id)
                
                if pdf_path and Path(pdf_path).exists():
                    # Update scan result with PDF path
                    result.pdf_report_path = pdf_path
                    scan_results_store[scan_id] = result
                    
                    filename = f"threat_analysis_{result.lead.domain}_{datetime.now().strftime('%Y%m%d')}.pdf"
                    
                    logger.info(f"Generated PDF on-demand for scan {scan_id}: {pdf_path}")
                    return FileResponse(
                        path=pdf_path,
                        filename=filename,
                        media_type='application/pdf'
                    )
                else:
                    raise HTTPException(status_code=500, detail="Failed to generate PDF report")
                    
            except Exception as pdf_error:
                logger.error(f"On-demand PDF generation failed for {scan_id}: {pdf_error}")
                raise HTTPException(status_code=500, detail="PDF report not available and generation failed")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export PDF failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/list")
async def list_pdf_reports():
    """List all available PDF reports"""
    try:
        from modules.pdf_generator import PDFReportGenerator
        pdf_generator = PDFReportGenerator()
        
        reports = pdf_generator.list_generated_reports()
        
        # Enrich with scan data if available
        enriched_reports = []
        for report in reports:
            enriched_report = report.copy()
            scan_id = report.get('scan_id')
            
            if scan_id and scan_id in scan_results_store:
                scan_result = scan_results_store[scan_id]
                enriched_report.update({
                    'domain': scan_result.lead.domain,
                    'company_name': scan_result.lead.company_name,
                    'risk_score': scan_result.risk_score.overall_score if scan_result.risk_score else None,
                    'risk_category': scan_result.risk_score.risk_category if scan_result.risk_score else None,
                    'vulnerabilities_count': len(scan_result.vulnerabilities),
                    'scan_completed_at': scan_result.scan_completed_at.isoformat() if scan_result.scan_completed_at else None
                })
            
            enriched_reports.append(enriched_report)
        
        return APIResponse(
            message=f"Found {len(reports)} PDF reports",
            data={
                "reports": enriched_reports,
                "total_reports": len(reports)
            }
        )
    
    except Exception as e:
        logger.error(f"List PDF reports failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


def generate_scan_csv(scan_result: ScanResult) -> str:
    """Generate CSV content from scan result"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header information
    writer.writerow(['Cyber Insurance Scanner Report'])
    writer.writerow(['Domain', scan_result.lead.domain])
    writer.writerow(['Company', scan_result.lead.company_name])
    writer.writerow(['Scan Date', scan_result.scan_started_at])
    writer.writerow(['Scan Status', scan_result.scan_status])
    
    if scan_result.risk_score:
        writer.writerow(['Risk Score', scan_result.risk_score.overall_score])
        writer.writerow(['Risk Category', scan_result.risk_score.risk_category])
    
    writer.writerow([])  # Empty row
    
    # Assets
    writer.writerow(['DISCOVERED ASSETS'])
    writer.writerow(['Subdomain', 'IP Address', 'Protocol', 'Port', 'Title', 'Technologies'])
    
    for asset in scan_result.assets:
        writer.writerow([
            asset.subdomain,
            asset.ip_address,
            asset.protocol,
            asset.port,
            asset.title,
            ', '.join(asset.tech_stack)
        ])
    
    writer.writerow([])  # Empty row
    
    # Port scan results
    writer.writerow(['OPEN PORTS'])
    writer.writerow(['IP Address', 'Port', 'Protocol', 'Service', 'Version', 'State'])
    
    for port in scan_result.port_scan_results:
        if port.state == 'open':
            writer.writerow([
                port.ip_address,
                port.port,
                port.protocol,
                port.service,
                port.version,
                port.state
            ])
    
    writer.writerow([])  # Empty row
    
    # Vulnerabilities
    writer.writerow(['VULNERABILITIES'])
    writer.writerow(['CVE ID', 'Severity', 'CVSS Score', 'Service', 'Port', 'Description'])
    
    for vuln in scan_result.vulnerabilities:
        writer.writerow([
            vuln.cve_id,
            vuln.severity,
            vuln.cvss_score,
            vuln.affected_service,
            vuln.port,
            vuln.description
        ])
    
    return output.getvalue()


def generate_scan_html(scan_result: ScanResult) -> str:
    """Generate comprehensive HTML report from scan result"""
    
    # Calculate summary stats
    total_assets = len(scan_result.assets)
    total_vulnerabilities = len(scan_result.vulnerabilities)
    # PERFORMANCE OPTIMIZATION: Use optimized port filtering
    open_ports = len(get_open_ports(scan_result.port_scan_results))
    
    # Vulnerability severity counts
    vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in scan_result.vulnerabilities:
        if vuln.severity in vuln_counts:
            vuln_counts[vuln.severity] += 1
    
    # Risk level color
    risk_color = "success"
    if scan_result.risk_score:
        if scan_result.risk_score.overall_score >= 75:
            risk_color = "danger"
        elif scan_result.risk_score.overall_score >= 50:
            risk_color = "warning"
        elif scan_result.risk_score.overall_score >= 25:
            risk_color = "info"
    
    # Generate HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.lead.domain}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .header-section {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem 0; }}
        .stat-card {{ border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.2s; }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; color: white; }}
        .vuln-card {{ border-left: 4px solid #007bff; margin-bottom: 1rem; }}
        .asset-card {{ border-left: 4px solid #28a745; }}
        .port-card {{ border-left: 4px solid #6f42c1; }}
        .mitre-badge {{ background: #2c3e50; color: white; }}
        .footer-section {{ background: #f8f9fa; padding: 2rem 0; margin-top: 3rem; }}
        @media print {{
            .no-print {{ display: none !important; }}
            body {{ background: white !important; }}
        }}
    </style>
</head>
<body>
    <!-- Header Section -->
    <div class="header-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="fas fa-shield-alt me-3"></i>Security Scan Report</h1>
                    <h2 class="h4 mb-0">{scan_result.lead.domain}</h2>
                    <p class="mb-0 opacity-75">{scan_result.lead.company_name}</p>
                </div>
                <div class="col-md-4 text-end">
                    <div class="bg-white bg-opacity-20 rounded p-3">
                        <h5 class="mb-1">Risk Score</h5>
                        <h2 class="mb-0 text-{risk_color}">
                            {scan_result.risk_score.overall_score if scan_result.risk_score else 0:.1f}/100
                        </h2>
                        <small>{scan_result.risk_score.risk_category.title() if scan_result.risk_score else 'Unknown'} Risk</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container my-5">
        <!-- Executive Summary -->
        <div class="row mb-5">
            <div class="col-12">
                <h3><i class="fas fa-chart-pie me-2"></i>Executive Summary</h3>
                <div class="row g-4">
                    <div class="col-md-3">
                        <div class="card stat-card text-center p-3">
                            <h4 class="text-primary mb-1">{total_assets}</h4>
                            <small class="text-muted">Assets Discovered</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-center p-3">
                            <h4 class="text-info mb-1">{open_ports}</h4>
                            <small class="text-muted">Open Ports</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-center p-3">
                            <h4 class="text-warning mb-1">{total_vulnerabilities}</h4>
                            <small class="text-muted">Vulnerabilities</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stat-card text-center p-3">
                            <h4 class="text-{risk_color} mb-1">{scan_result.risk_score.risk_category.title() if scan_result.risk_score else 'Unknown'}</h4>
                            <small class="text-muted">Risk Level</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Summary -->
        <div class="row mb-5">
            <div class="col-12">
                <h3><i class="fas fa-exclamation-triangle me-2"></i>Vulnerability Summary</h3>
                <div class="row g-3">
                    <div class="col-md-3">
                        <div class="card severity-critical text-center p-3">
                            <h4 class="mb-1">{vuln_counts['CRITICAL']}</h4>
                            <small>Critical</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card severity-high text-center p-3">
                            <h4 class="mb-1">{vuln_counts['HIGH']}</h4>
                            <small>High</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card severity-medium text-center p-3">
                            <h4 class="mb-1">{vuln_counts['MEDIUM']}</h4>
                            <small>Medium</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card severity-low text-center p-3">
                            <h4 class="mb-1">{vuln_counts['LOW']}</h4>
                            <small>Low</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Vulnerabilities -->
        {generate_vulnerabilities_html(scan_result.vulnerabilities)}

        <!-- Discovered Assets -->
        {generate_assets_html(scan_result.assets)}

        <!-- Open Ports -->
        {generate_ports_html(scan_result.port_scan_results)}

        <!-- Risk Assessment -->
        {generate_risk_assessment_html(scan_result.risk_score)}
    </div>

    <!-- Footer -->
    <div class="footer-section">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h6>Scan Information</h6>
                    <p class="small mb-1"><strong>Scan ID:</strong> {scan_result.scan_id}</p>
                    <p class="small mb-1"><strong>Started:</strong> {scan_result.scan_started_at.strftime('%Y-%m-%d %H:%M:%S') if scan_result.scan_started_at else 'Unknown'}</p>
                    <p class="small mb-1"><strong>Completed:</strong> {scan_result.scan_completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan_result.scan_completed_at else 'Unknown'}</p>
                    <p class="small mb-0"><strong>Duration:</strong> {scan_result.scan_duration:.2f} seconds</p>
                </div>
                <div class="col-md-6 text-end">
                    <h6>Generated By</h6>
                    <p class="small mb-0">Cyber Insurance Scanner</p>
                    <p class="small mb-0">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
    return html


def generate_vulnerabilities_html(vulnerabilities: List) -> str:
    """Generate HTML section for vulnerabilities with proper XSS protection"""
    if not vulnerabilities:
        return """
        <div class="row mb-5">
            <div class="col-12">
                <h3><i class="fas fa-shield-check me-2 text-success"></i>Vulnerabilities</h3>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    Great news! No security vulnerabilities were detected during the scan.
                </div>
            </div>
        </div>
        """
    
    html = '<div class="row mb-5"><div class="col-12"><h3><i class="fas fa-bug me-2"></i>Detailed Vulnerabilities</h3>'
    
    # PERFORMANCE OPTIMIZATION: Group vulnerabilities by severity using dict for O(n) complexity
    # Instead of filtering the list multiple times (O(n*m)), group once (O(n))
    severity_groups = {}
    for vuln in vulnerabilities:
        severity = vuln.severity
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(vuln)
    
    # Process in priority order
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    for severity in severity_order:
        severity_vulns = severity_groups.get(severity, [])
        if not severity_vulns:
            continue
            
        # Safely escape severity level
        safe_severity = escape_html(severity)
        severity_color = get_severity_color(severity)  # This function should be safe
        
        html += create_safe_html_snippet(
            '<h4 class="mt-4 mb-3 text-{color}"><i class="fas fa-exclamation-circle me-2"></i>{severity} Vulnerabilities ({count})</h4>',
            color=severity_color,
            severity=safe_severity,
            count=len(severity_vulns)
        )
        
        for vuln in severity_vulns:
            # Safely escape all vulnerability data
            safe_cve_id = escape_html(vuln.cve_id) if vuln.cve_id else "UNKNOWN-CVE"
            safe_description = sanitize_html_content(vuln.description) if vuln.description else "No description available"
            safe_affected_service = escape_html(vuln.affected_service) if vuln.affected_service else ""
            safe_remediation = sanitize_html_content(vuln.remediation_advice) if hasattr(vuln, 'remediation_advice') and vuln.remediation_advice else ""
            safe_port = sanitize_port_number(vuln.port) if vuln.port else None
            safe_cvss = max(0.0, min(10.0, float(vuln.cvss_score))) if vuln.cvss_score else 0.0
            
            # Build MITRE badges safely
            mitre_badges = ""
            if hasattr(vuln, 'mitre_techniques') and vuln.mitre_techniques:
                for technique in vuln.mitre_techniques:
                    safe_technique_id = escape_html(technique.technique_id) if hasattr(technique, 'technique_id') else ""
                    if safe_technique_id:
                        mitre_badges += f'<span class="badge mitre-badge me-1">{safe_technique_id}</span>'
            
            # Build remediation section safely
            remediation_html = ""
            if safe_remediation:
                remediation_html = f'<div class="mt-2"><strong>Remediation:</strong> {safe_remediation}</div>'
            
            # Build risk factors safely
            risk_factors_html = ""
            if hasattr(vuln, 'risk_factors') and vuln.risk_factors:
                safe_factors = [escape_html(factor) for factor in vuln.risk_factors if factor]
                if safe_factors:
                    factors_list = ''.join([f'<li>{factor}</li>' for factor in safe_factors])
                    risk_factors_html = f'<div class="mt-2"><strong>Risk Factors:</strong><ul class="mb-0">{factors_list}</ul></div>'
            
            # Build service and port badges safely
            service_badge = f'<span class="badge bg-secondary me-2">{safe_affected_service}</span>' if safe_affected_service else ''
            port_badge = f'<span class="badge bg-dark me-2">Port {safe_port}</span>' if safe_port else ''
            exploit_badge = '<span class="badge bg-danger">Exploit Available</span>' if vuln.exploit_available else ''
            
            # Build severity and CVSS badges
            severity_class = {
                'CRITICAL': 'danger',
                'HIGH': 'warning', 
                'MEDIUM': 'info',
                'LOW': 'success'
            }.get(severity, 'secondary')
            
            cvss_class = 'danger' if safe_cvss >= 7 else 'warning' if safe_cvss >= 4 else 'success'
            
            html += f"""
            <div class="card vuln-card mb-3">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h5 class="card-title">{safe_cve_id}</h5>
                            <div class="mb-2">
                                <span class="badge severity-{severity.lower()} me-2">{safe_severity}</span>
                                <span class="badge bg-{cvss_class} me-2">CVSS {safe_cvss:.1f}</span>
                                {service_badge}
                                {port_badge}
                                {exploit_badge}
                            </div>
                            {mitre_badges}
                        </div>
                    </div>
                    <p class="card-text mt-3">{safe_description}</p>
                    {remediation_html}
                    {risk_factors_html}
                </div>
            </div>
            """
    
    html += '</div></div>'
    return html


def generate_assets_html(assets: List) -> str:
    """Generate HTML section for discovered assets"""
    if not assets:
        return ""
    
    html = f'<div class="row mb-5"><div class="col-12"><h3><i class="fas fa-server me-2"></i>Discovered Assets ({len(assets)})</h3>'
    
    # Group by IP address for consolidation
    ip_groups = {}
    for asset in assets:
        ip = asset.ip_address
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(asset)
    
    for ip, ip_assets in ip_groups.items():
        # Consolidate technologies
        all_technologies = set()
        for asset in ip_assets:
            all_technologies.update(asset.tech_stack)
        
        html += f"""
        <div class="card asset-card mb-3">
            <div class="card-header bg-light">
                <h6 class="mb-0"><i class="fas fa-network-wired me-2"></i>IP Address: {ip}</h6>
                {f'<div class="mt-1"><strong>Technologies:</strong> {", ".join(sorted(all_technologies))}</div>' if all_technologies else ''}
            </div>
            <div class="card-body">
                <div class="row">
        """
        
        for asset in ip_assets:
            status_color = "success" if asset.status_code == 200 else "warning" if asset.status_code in [301, 302] else "danger"
            html += f"""
                    <div class="col-md-6 mb-3">
                        <div class="border rounded p-3">
                            <h6><a href="{asset.protocol}://{asset.subdomain}:{asset.port}" target="_blank">{asset.subdomain}</a></h6>
                            <div class="small">
                                <span class="badge bg-{status_color} me-2">{asset.status_code}</span>
                                <span class="badge bg-secondary">{asset.protocol.upper()}:{asset.port}</span>
                            </div>
                            <p class="small text-muted mt-2 mb-0">{asset.title[:100]}{'...' if len(asset.title) > 100 else ''}</p>
                        </div>
                    </div>
            """
        
        html += """
                </div>
            </div>
        </div>
        """
    
    html += '</div></div>'
    return html


def generate_ports_html(port_results: List) -> str:
    """Generate HTML section for open ports with proper security and complete risk classification"""
    # PERFORMANCE OPTIMIZATION: Use optimized port filtering
    open_ports = get_open_ports(port_results)
    if not open_ports:
        return ""
    
    html = f'<div class="row mb-5"><div class="col-12"><h3><i class="fas fa-door-open me-2"></i>Open Ports ({len(open_ports)})</h3>'
    
    # Enhanced risk classification - more comprehensive port risk assessment
    high_risk_ports = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 27017, 50000}
    medium_risk_ports = {22, 25, 53, 80, 110, 143, 389, 443, 993, 995, 1080, 3128, 8080, 8443, 9200}
    
    def get_port_risk_classification(port_num, service_name=""):
        """Determine comprehensive risk level for a port"""
        if port_num in high_risk_ports:
            return "danger", "High Risk"
        elif port_num in medium_risk_ports:
            return "warning", "Medium Risk"
        elif port_num < 1024:  # Well-known ports
            return "info", "Standard Service"
        else:
            return "secondary", "Custom Service"
    
    # Group by IP address using dict for better performance
    ip_groups = {}
    for port in open_ports:
        safe_ip = sanitize_ip_address(port.ip_address)
        if safe_ip:
            if safe_ip not in ip_groups:
                ip_groups[safe_ip] = []
            ip_groups[safe_ip].append(port)
    
    for ip, ip_ports in ip_groups.items():
        # Sort ports for consistent display
        ip_ports.sort(key=lambda x: x.port)
        
        # Safely escape IP address
        safe_ip = escape_html(ip)
        
        html += f"""
        <div class="card port-card mb-3">
            <div class="card-header bg-light">
                <h6 class="mb-0"><i class="fas fa-server me-2"></i>IP Address: {safe_ip}</h6>
                <small class="text-muted">{len(ip_ports)} open ports detected</small>
            </div>
            <div class="card-body">
                <div class="row">
        """
        
        for port in ip_ports:
            # Validate and sanitize port data
            safe_port = sanitize_port_number(port.port)
            if not safe_port:
                continue  # Skip invalid ports
                
            safe_protocol = escape_html(port.protocol) if port.protocol else "tcp"
            safe_service = escape_html(port.service) if port.service else "Unknown"
            safe_version = escape_html(port.version) if port.version else ""
            safe_state = escape_html(port.state) if port.state else "unknown"
            
            # Get comprehensive risk classification
            risk_class, risk_text = get_port_risk_classification(safe_port, safe_service)
            
            # Truncate long service names and versions for display
            display_service = safe_service[:20] + "..." if len(safe_service) > 20 else safe_service
            display_version = safe_version[:30] + "..." if len(safe_version) > 30 else safe_version
            
            # Additional security indicators
            security_indicators = []
            if safe_port in high_risk_ports:
                security_indicators.append('<span class="badge bg-danger">High Risk</span>')
            
            if safe_service.lower() in ['ssh', 'telnet', 'rdp']:
                security_indicators.append('<span class="badge bg-warning">Remote Access</span>')
                
            if safe_service.lower() in ['mysql', 'postgresql', 'mssql', 'oracle']:
                security_indicators.append('<span class="badge bg-info">Database</span>')
                
            if safe_port in [80, 443, 8080, 8443]:
                security_indicators.append('<span class="badge bg-primary">Web Service</span>')
                
            indicators_html = ' '.join(security_indicators) if security_indicators else ''
            
            html += f"""
                    <div class="col-md-4 mb-3">
                        <div class="border rounded p-3 h-100">
                            <h6 class="text-{risk_class}">
                                Port {safe_port}/{safe_protocol}
                                <span class="badge bg-{risk_class} ms-2">{risk_text}</span>
                            </h6>
                            <div class="small mb-2">
                                <strong>Service:</strong> <span title="{safe_service}">{display_service}</span><br>
                                {f'<strong>Version:</strong> <span title="{safe_version}">{display_version}</span><br>' if safe_version else ''}
                                <strong>State:</strong> {safe_state}<br>
                                <strong>Risk Level:</strong> <span class="text-{risk_class}">{risk_text}</span>
                            </div>
                            {f'<div class="mt-2">{indicators_html}</div>' if indicators_html else ''}
                        </div>
                    </div>
            """
        
        html += """
                </div>
            </div>
        </div>
        """
    
    # Add summary statistics
    total_high_risk = len([p for p in open_ports if p.port in high_risk_ports])
    total_medium_risk = len([p for p in open_ports if p.port in medium_risk_ports])
    
    if total_high_risk > 0 or total_medium_risk > 0:
        html += f"""
        <div class="alert alert-info">
            <h6><i class="fas fa-info-circle me-2"></i>Port Risk Summary</h6>
            <div class="row">
                <div class="col-md-4">
                    <strong>High Risk Ports:</strong> {total_high_risk}
                </div>
                <div class="col-md-4">
                    <strong>Medium Risk Ports:</strong> {total_medium_risk}
                </div>
                <div class="col-md-4">
                    <strong>Total Open Ports:</strong> {len(open_ports)}
                </div>
            </div>
        </div>
        """
    
    html += '</div></div>'
    return html


def generate_risk_assessment_html(risk_score) -> str:
    """Generate HTML section for risk assessment"""
    if not risk_score:
        return ""
    
    color_map = {
        'critical': 'danger',
        'high': 'warning', 
        'medium': 'info',
        'low': 'success'
    }
    
    color = color_map.get(risk_score.risk_category.lower(), 'secondary')
    
    html = f"""
    <div class="row mb-5">
        <div class="col-12">
            <h3><i class="fas fa-chart-line me-2"></i>Risk Assessment</h3>
            <div class="card">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h5>Overall Risk Score</h5>
                            <h2 class="text-{color}">{risk_score.overall_score:.1f}/100</h2>
                            <p class="text-muted">Risk Category: <strong class="text-{color}">{risk_score.risk_category.title()}</strong></p>
                        </div>
                        <div class="col-md-6">
                            <h6>Component Scores</h6>
                            <div class="small">
                                <div class="d-flex justify-content-between">
                                    <span>Port Risk:</span>
                                    <span>{risk_score.port_risk_score:.1f}/100</span>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <span>Vulnerability Risk:</span>
                                    <span>{risk_score.vulnerability_risk_score:.1f}/100</span>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <span>SSL Risk:</span>
                                    <span>{risk_score.ssl_risk_score:.1f}/100</span>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <span>Service Risk:</span>
                                    <span>{risk_score.service_risk_score:.1f}/100</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    return html


def get_severity_color(severity: str) -> str:
    """Get Bootstrap color for severity level"""
    color_map = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info', 
        'LOW': 'success'
    }
    return color_map.get(severity, 'secondary')


@app.get("/api/test/vulnerabilities/detailed")
async def test_vulnerabilities():
    """Test endpoint to verify vulnerability display functionality"""
    mock_data = {
        "success": True,
        "data": {
            "status": "completed",
            "progress": {
                "current_phase": "completed",
                "overall_progress": 100.0,
                "phases_completed": 10,
                "total_phases": 10,
                "current_task": "Scan completed",
                "status": "completed",
                "vulnerabilities": []
            },
            "results": {
                "scan_id": "test-vuln-display",
                "lead": {
                    "domain": "test-vulnerabilities.com",
                    "company_name": "Test Vulnerabilities Display",
                    "timestamp": "2025-07-13 08:50:00"
                },
                "assets": [
                    {
                        "subdomain": "www",
                        "full_domain": "www.test-vulnerabilities.com",
                        "ip_address": "192.168.1.100",
                        "tech_stack": ["Apache", "PHP"],
                        "title": "Test Site",
                        "server_header": "Apache/2.4.41"
                    }
                ],
                "port_scan_results": [
                    {
                        "ip": "192.168.1.100",
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "version": "Apache httpd 2.4.41"
                    },
                    {
                        "ip": "192.168.1.100",
                        "port": 443,
                        "state": "open",
                        "service": "https",
                        "version": "Apache httpd 2.4.41"
                    }
                ],
                "vulnerabilities": [
                    {
                        "cve_id": "WEB-X-FRAME-OPTIONS",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "description": "Missing X-Frame-Options header allows clickjacking attacks",
                        "affected_service": "HTTP",
                        "affected_version": "Apache/2.4.41",
                        "port": 80,
                        "exploit_available": False,
                        "patch_available": True,
                        "discovered_at": "2025-07-13 08:50:00"
                    },
                    {
                        "cve_id": "WEB-X-CONTENT-TYPE-OPTIONS",
                        "severity": "LOW",
                        "cvss_score": 3.1,
                        "description": "Missing X-Content-Type-Options header allows MIME type sniffing",
                        "affected_service": "HTTP",
                        "affected_version": "Apache/2.4.41",
                        "port": 80,
                        "exploit_available": False,
                        "patch_available": True,
                        "discovered_at": "2025-07-13 08:50:00"
                    },
                    {
                        "cve_id": "WEB-HSTS-MISSING",
                        "severity": "MEDIUM",
                        "cvss_score": 5.4,
                        "description": "Missing Strict-Transport-Security header allows protocol downgrade attacks",
                        "affected_service": "HTTPS",
                        "affected_version": "Apache/2.4.41",
                        "port": 443,
                        "exploit_available": False,
                        "patch_available": True,
                        "discovered_at": "2025-07-13 08:50:00"
                    },
                    {
                        "cve_id": "WEB-CSP-MISSING",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "description": "Missing Content-Security-Policy header allows XSS attacks",
                        "affected_service": "HTTP",
                        "affected_version": "Apache/2.4.41",
                        "port": 80,
                        "exploit_available": False,
                        "patch_available": True,
                        "discovered_at": "2025-07-13 08:50:00"
                    },
                    {
                        "cve_id": "WEB-HTTP-INSECURE",
                        "severity": "MEDIUM",
                        "cvss_score": 5.0,
                        "description": "Unencrypted HTTP connection detected for sensitive content",
                        "affected_service": "HTTP",
                        "affected_version": "Apache/2.4.41",
                        "port": 80,
                        "exploit_available": False,
                        "patch_available": True,
                        "discovered_at": "2025-07-13 08:50:00"
                    }
                ],
                "scan_completed_at": "2025-07-13 08:50:00",
                "scan_duration": 180.5,
                "scan_status": "completed"
            }
        }
    }
    return mock_data


@app.get("/test-vulnerabilities")
async def test_vulnerabilities_page(request: Request):
    """Test page for vulnerability display functionality"""
    return templates.TemplateResponse("test_vulnerabilities.html", {"request": request})


@app.get("/")
async def dashboard():
    """Serve the main dashboard interface"""
    return FileResponse("templates/index.html")


@app.get("/api/scan/{scan_id}/sales-intelligence")
async def get_sales_intelligence(scan_id: str, industry: str = "general"):
    """
    Get sales-specific intelligence for a completed scan
    Provides actionable insights for sales outreach and prioritization
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML-based sales intelligence not available")
    
    try:
        # Get scan result
        result_file = REPORTS_DIR / f"{scan_id}.json"
        
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Scan not found")
        
        with open(result_file, 'r') as f:
            scan_data = json.load(f)
        
        # Convert to ScanResult object
        scan_result = ScanResult(**scan_data)
        
        # Generate sales intelligence
        sales_generator = SalesIntelligenceGenerator()
        intelligence = sales_generator.generate_sales_intelligence(scan_result, industry)
        
        # Generate exploit predictions for top vulnerabilities
        ml_predictor = MLExploitPredictor()
        exploit_predictions = []
        
        # Sort vulnerabilities by severity and get top 10
        sorted_vulns = sorted(scan_result.vulnerabilities, 
                            key=lambda v: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(v.severity, 0), 
                            reverse=True)[:10]
        
        for vuln in sorted_vulns:
            prediction = ml_predictor.predict_exploit_likelihood(vuln, scan_result.vulnerabilities)
            exploit_predictions.append({
                'cve_id': prediction.cve_id,
                'exploit_likelihood': round(prediction.exploit_likelihood, 3),
                'confidence_score': round(prediction.confidence_score, 3),
                'risk_factors': prediction.risk_factors,
                'exploit_complexity': prediction.exploit_complexity,
                'time_to_exploit': prediction.time_to_exploit,
                'mitigation_priority': prediction.mitigation_priority,
                'sales_impact_score': round(prediction.sales_impact_score, 2)
            })
        
        # Create comprehensive sales response
        sales_response = {
            'scan_id': scan_id,
            'domain': scan_result.lead.domain,
            'company_name': scan_result.lead.company_name,
            'industry': industry,
            'generated_at': datetime.now().isoformat(),
            
            # Core sales intelligence
            'prospect_risk_level': intelligence.prospect_risk_level,
            'urgency_score': round(intelligence.urgency_score, 2),
            'estimated_attack_cost': intelligence.estimated_attack_cost,
            
            # Immediate action items
            'immediate_concerns': intelligence.immediate_concerns,
            'business_impact_summary': intelligence.business_impact_summary,
            
            # Sales positioning
            'recommended_solutions': intelligence.recommended_solutions,
            'competitive_advantages': intelligence.competitive_advantages,
            'compliance_risks': intelligence.compliance_risks,
            
            # Detailed vulnerability intelligence
            'exploit_predictions': exploit_predictions,
            
            # Executive summary for outreach
            'executive_summary': _generate_executive_summary(intelligence, scan_result),
            'call_to_action': _generate_call_to_action(intelligence),
            
            # Statistics for reference
            'vulnerability_statistics': {
                'total_vulnerabilities': len(scan_result.vulnerabilities),
                'critical_vulnerabilities': len([v for v in scan_result.vulnerabilities if v.severity == 'CRITICAL']),
                'high_vulnerabilities': len([v for v in scan_result.vulnerabilities if v.severity == 'HIGH']),
                'exploitable_vulnerabilities': len([v for v in scan_result.vulnerabilities if v.exploit_available]),
                'average_cvss_score': round(sum(v.cvss_score or 0 for v in scan_result.vulnerabilities) / max(len(scan_result.vulnerabilities), 1), 2)
            }
        }
        
        return APIResponse(
            success=True,
            message="Sales intelligence generated successfully",
            data=sales_response
        )
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan result not found")
    except Exception as e:
        logger.error(f"Sales intelligence generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sales intelligence generation failed: {str(e)}")


def _generate_executive_summary(intelligence: Any, scan_result: Any) -> str:
    """Generate executive-friendly summary for sales outreach"""
    domain = scan_result.lead.domain
    company = scan_result.lead.company_name or domain
    risk_level = intelligence.prospect_risk_level.lower()
    
    if intelligence.prospect_risk_level == "CRITICAL":
        return f"Security assessment of {company} ({domain}) reveals critical vulnerabilities requiring immediate attention. " \
               f"With an estimated potential attack cost of ${intelligence.estimated_attack_cost:,}, " \
               f"immediate security improvements are essential to protect business operations and customer data."
    
    elif intelligence.prospect_risk_level == "HIGH":
        return f"Security evaluation of {company} ({domain}) identifies significant security gaps that could " \
               f"impact business continuity. Risk mitigation through enhanced security controls is recommended " \
               f"to prevent potential ${intelligence.estimated_attack_cost:,} in damages."
    
    elif intelligence.prospect_risk_level == "MEDIUM":
        return f"Security review of {company} ({domain}) shows moderate risk levels with opportunities for " \
               f"proactive security enhancement. Addressing identified vulnerabilities will strengthen " \
               f"overall security posture and reduce business risk."
    
    else:
        return f"Security assessment of {company} ({domain}) indicates a relatively strong security foundation " \
               f"with some areas for improvement. Continued security monitoring and best practices will " \
               f"maintain robust protection against evolving threats."


def _generate_call_to_action(intelligence: Any) -> str:
    """Generate specific call to action based on risk level"""
    if intelligence.urgency_score >= 8.0:
        return "Schedule an immediate security consultation to address critical vulnerabilities and prevent potential breaches."
    elif intelligence.urgency_score >= 6.0:
        return "Book a security assessment meeting within the next week to discuss risk mitigation strategies."
    elif intelligence.urgency_score >= 4.0:
        return "Arrange a security review call to explore proactive protection measures and security improvements."
    else:
        return "Consider a comprehensive security evaluation to maintain strong defenses against emerging threats."


if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=settings.api_workers,
        reload=settings.debug
    ) 