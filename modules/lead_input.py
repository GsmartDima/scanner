"""
Lead Input Module
Handles lead ingestion from CSV/JSON files and validation
"""
import csv
import json
import pandas as pd
import uuid
import re
from typing import List, Dict, Any, Tuple
from pathlib import Path
import aiofiles
from fastapi import UploadFile
import logging

from models import Lead, FileUploadResponse
from config import settings

logger = logging.getLogger(__name__)


class LeadInputProcessor:
    """Processes lead input from various sources"""
    
    def __init__(self):
        self.supported_formats = ['.csv', '.json', '.xlsx']
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    def _secure_filename(self, filename: str) -> str:
        """
        Secure filename implementation to prevent path traversal attacks
        Based on werkzeug's secure_filename but self-contained
        """
        # Remove path separators and dangerous characters
        filename = re.sub(r'[^\w\s\.-]', '', filename)
        filename = re.sub(r'[\\/]', '', filename)  # Remove path separators
        filename = re.sub(r'\.\.+', '.', filename)  # Replace multiple dots with single dot
        filename = filename.strip('.')  # Remove leading/trailing dots
        filename = filename.strip()  # Remove whitespace
        
        # Ensure we have a valid filename
        if not filename or filename in ('.', '..'):
            filename = 'upload'
        
        return filename
    
    async def process_file_upload(self, file: UploadFile) -> FileUploadResponse:
        """Process uploaded file and extract leads"""
        try:
            # Validate file
            await self._validate_file(file)
            
            # Save uploaded file
            file_path = await self._save_uploaded_file(file)
            
            # Process file based on extension
            leads, errors = await self._process_file(file_path)
            
            # Validate leads
            valid_leads, invalid_leads, validation_errors = self._validate_leads(leads)
            
            # Create response
            response = FileUploadResponse(
                filename=file.filename,
                file_size=file.size,
                leads_count=len(leads),
                valid_leads=len(valid_leads),
                invalid_leads=len(invalid_leads),
                errors=errors + validation_errors
            )
            
            logger.info(f"Processed file {file.filename}: {len(valid_leads)} valid leads, {len(invalid_leads)} invalid")
            
            return response, valid_leads
            
        except Exception as e:
            logger.error(f"Error processing file upload: {str(e)}")
            raise
    
    async def _validate_file(self, file: UploadFile) -> None:
        """Validate uploaded file"""
        if not file.filename:
            raise ValueError("No filename provided")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in self.supported_formats:
            raise ValueError(f"Unsupported file format. Supported: {self.supported_formats}")
        
        if file.size > self.max_file_size:
            raise ValueError(f"File too large. Maximum size: {self.max_file_size} bytes")
    
    async def _save_uploaded_file(self, file: UploadFile) -> Path:
        """Save uploaded file to disk with path traversal protection"""
        if not file.filename:
            raise ValueError("No filename provided")
        
        # Validate filename format - reject filenames with suspicious patterns
        if not file.filename.strip():
            raise ValueError("Empty filename not allowed")
        
        # Check for path traversal attempts
        if '..' in file.filename or '/' in file.filename or '\\' in file.filename:
            logger.warning(f"Path traversal attempt detected in filename: {file.filename}")
            raise ValueError("Invalid filename - path traversal attempt detected")
        
        # Generate safe filename with UUID prefix to prevent collisions
        safe_filename = self._secure_filename(file.filename)
        if not safe_filename:
            safe_filename = "upload"
        
        # Add UUID prefix and preserve original extension
        file_extension = Path(file.filename).suffix.lower()
        unique_filename = f"{uuid.uuid4().hex}_{safe_filename}"
        if file_extension and not unique_filename.endswith(file_extension):
            unique_filename += file_extension
        
        file_path = Path(settings.upload_dir) / unique_filename
        
        # Validate final path is within intended directory (path traversal protection)
        upload_dir_resolved = Path(settings.upload_dir).resolve()
        file_path_resolved = file_path.resolve()
        
        if not str(file_path_resolved).startswith(str(upload_dir_resolved)):
            logger.error(f"Path traversal detected: {file_path_resolved} not within {upload_dir_resolved}")
            raise ValueError("Path traversal attack detected")
        
        # Save file securely
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        logger.info(f"File saved securely: {file.filename} -> {unique_filename}")
        return file_path
    
    async def _process_file(self, file_path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Process file based on its format"""
        errors = []
        
        try:
            file_extension = file_path.suffix.lower()
            
            if file_extension == '.csv':
                return await self._process_csv(file_path)
            elif file_extension == '.json':
                return await self._process_json(file_path)
            elif file_extension == '.xlsx':
                return await self._process_excel(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
                
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            errors.append(f"File processing error: {str(e)}")
            return [], errors
    
    async def _process_csv(self, file_path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Process CSV file"""
        leads = []
        errors = []
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            # Parse CSV
            csv_reader = csv.DictReader(content.splitlines())
            
            for row_num, row in enumerate(csv_reader, start=2):  # Start from 2 (header is row 1)
                try:
                    # Map CSV columns to lead fields
                    lead_data = self._map_csv_row(row)
                    if lead_data:
                        leads.append(lead_data)
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
            
        except Exception as e:
            errors.append(f"CSV parsing error: {str(e)}")
        
        return leads, errors
    
    async def _process_json(self, file_path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Process JSON file"""
        leads = []
        errors = []
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            data = json.loads(content)
            
            # Handle different JSON structures
            if isinstance(data, list):
                leads = data
            elif isinstance(data, dict):
                if 'leads' in data:
                    leads = data['leads']
                elif 'data' in data:
                    leads = data['data']
                else:
                    leads = [data]
            else:
                errors.append("Invalid JSON structure")
                
        except json.JSONDecodeError as e:
            errors.append(f"JSON parsing error: {str(e)}")
        except Exception as e:
            errors.append(f"File reading error: {str(e)}")
        
        return leads, errors
    
    async def _process_excel(self, file_path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Process Excel file"""
        leads = []
        errors = []
        
        try:
            # Read Excel file
            df = pd.read_excel(file_path)
            
            # Convert to list of dictionaries
            for index, row in df.iterrows():
                try:
                    lead_data = self._map_excel_row(row.to_dict())
                    if lead_data:
                        leads.append(lead_data)
                except Exception as e:
                    errors.append(f"Row {index + 2}: {str(e)}")  # +2 for header and 0-based index
            
        except Exception as e:
            errors.append(f"Excel processing error: {str(e)}")
        
        return leads, errors
    
    def _map_csv_row(self, row: Dict[str, str]) -> Dict[str, Any]:
        """Map CSV row to lead data"""
        # Common column name variations
        domain_columns = ['domain', 'Domain', 'DOMAIN', 'website', 'Website', 'url', 'URL']
        company_columns = ['company', 'Company', 'COMPANY', 'company_name', 'Company Name', 'organization', 'Organization']
        
        domain = None
        company_name = None
        
        # Find domain column
        for col in domain_columns:
            if col in row and row[col]:
                domain = row[col].strip()
                # Clean up domain (remove protocol, paths, etc.)
                domain = self._clean_domain(domain)
                break
        
        # Find company name column
        for col in company_columns:
            if col in row and row[col]:
                company_name = row[col].strip()
                break
        
        if not domain:
            raise ValueError("No domain found in row")
        if not company_name:
            raise ValueError("No company name found in row")
        
        return {
            'domain': domain,
            'company_name': company_name
        }
    
    def _map_excel_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Map Excel row to lead data"""
        return self._map_csv_row(row)
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        if not domain:
            return domain
        
        # Remove protocol
        domain = domain.replace('http://', '').replace('https://', '')
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove trailing slash and path
        domain = domain.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        return domain.lower().strip()
    
    def _validate_leads(self, leads_data: List[Dict[str, Any]]) -> Tuple[List[Lead], List[Dict[str, Any]], List[str]]:
        """Validate lead data and create Lead objects"""
        valid_leads = []
        invalid_leads = []
        errors = []
        
        for i, lead_data in enumerate(leads_data):
            try:
                # Create Lead object (this will validate the data)
                lead = Lead(**lead_data)
                valid_leads.append(lead)
            except Exception as e:
                invalid_leads.append(lead_data)
                errors.append(f"Lead {i + 1}: {str(e)}")
        
        return valid_leads, invalid_leads, errors
    
    def remove_duplicates(self, leads: List[Lead]) -> List[Lead]:
        """Remove duplicate leads based on domain"""
        seen_domains = set()
        unique_leads = []
        
        for lead in leads:
            if lead.domain not in seen_domains:
                seen_domains.add(lead.domain)
                unique_leads.append(lead)
        
        logger.info(f"Removed {len(leads) - len(unique_leads)} duplicate leads")
        return unique_leads
    
    async def export_leads_to_csv(self, leads: List[Lead], output_path: Path) -> None:
        """Export leads to CSV file"""
        try:
            async with aiofiles.open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                await f.write('domain,company_name,timestamp\n')
                
                # Write leads
                for lead in leads:
                    line = f"{lead.domain},{lead.company_name},{lead.timestamp.isoformat()}\n"
                    await f.write(line)
                    
            logger.info(f"Exported {len(leads)} leads to {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting leads to CSV: {str(e)}")
            raise 