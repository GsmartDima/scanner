"""
Apollo.io CSV Parser Module
Converts Apollo.io company export data into scanner-compatible format
"""

import csv
import re
import logging
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import json

logger = logging.getLogger(__name__)

class ApolloParser:
    """Parser for Apollo.io company export CSV files"""
    
    def __init__(self):
        self.required_fields = ['Company', 'Website']
        self.optional_fields = [
            '# Employees', 'Industry', 'Annual Revenue', 'Technologies',
            'Short Description', 'Founded Year', 'Total Funding',
            'Company Phone', 'Company City', 'Company State', 'Company Country'
        ]
        self.parsed_data = []
        self.errors = []
        self.stats = {
            'total_rows': 0,
            'valid_companies': 0,
            'invalid_domains': 0,
            'missing_websites': 0,
            'enriched_data': 0
        }
    
    def clean_domain(self, website: str) -> Optional[str]:
        """Clean and extract domain from website URL"""
        if not website or website.strip() == '':
            return None
            
        # Remove common prefixes and clean
        website = website.strip().lower()
        if website.startswith('http://'):
            website = website[7:]
        elif website.startswith('https://'):
            website = website[8:]
        
        # Remove www prefix
        if website.startswith('www.'):
            website = website[4:]
            
        # Remove trailing slash and paths
        website = website.split('/')[0]
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, website):
            return website
        
        return None
    
    def parse_employee_count(self, emp_str: str) -> Optional[int]:
        """Parse employee count from various formats"""
        if not emp_str:
            return None
            
        # Remove commas and extract numbers
        emp_str = str(emp_str).replace(',', '').strip()
        
        # Handle ranges like "10-50" or "100+"
        if '-' in emp_str:
            try:
                return int(emp_str.split('-')[0])
            except:
                pass
        elif '+' in emp_str:
            try:
                return int(emp_str.replace('+', ''))
            except:
                pass
        else:
            try:
                return int(emp_str)
            except:
                pass
        
        return None
    
    def parse_revenue(self, revenue_str: str) -> Optional[int]:
        """Parse annual revenue from various formats"""
        if not revenue_str:
            return None
            
        revenue_str = str(revenue_str).replace(',', '').replace('$', '').strip()
        
        try:
            return int(revenue_str)
        except:
            return None
    
    def parse_technologies(self, tech_str: str) -> List[str]:
        """Parse technologies from comma-separated string"""
        if not tech_str:
            return []
            
        # Split by comma and clean each technology
        technologies = [tech.strip() for tech in str(tech_str).split(',')]
        return [tech for tech in technologies if tech and len(tech) > 1]
    
    def determine_priority(self, row_data: Dict) -> str:
        """Determine scanning priority based on company data"""
        priority = 'medium'  # default
        
        # High priority factors
        employee_count = self.parse_employee_count(row_data.get('# Employees', ''))
        revenue = self.parse_revenue(row_data.get('Annual Revenue', ''))
        technologies = self.parse_technologies(row_data.get('Technologies', ''))
        
        high_priority_conditions = [
            employee_count and employee_count >= 100,  # Large companies
            revenue and revenue >= 10000000,  # $10M+ revenue
            len(technologies) >= 10,  # Tech-heavy companies
            any(tech.lower() in ['aws', 'azure', 'google cloud', 'kubernetes'] for tech in technologies),  # Cloud infrastructure
        ]
        
        low_priority_conditions = [
            employee_count and employee_count <= 10,  # Very small companies
            revenue and revenue <= 1000000,  # <$1M revenue
        ]
        
        if any(high_priority_conditions):
            priority = 'high'
        elif any(low_priority_conditions):
            priority = 'low'
            
        return priority
    
    def enrich_company_data(self, row_data: Dict) -> Dict:
        """Enrich company data with additional metadata"""
        enriched = {
            'apollo_data': {
                'industry': row_data.get('Industry', '').strip(),
                'employee_count': self.parse_employee_count(row_data.get('# Employees', '')),
                'annual_revenue': self.parse_revenue(row_data.get('Annual Revenue', '')),
                'founded_year': row_data.get('Founded Year', '').strip(),
                'technologies': self.parse_technologies(row_data.get('Technologies', '')),
                'description': row_data.get('Short Description', '').strip(),
                'phone': row_data.get('Company Phone', '').strip(),
                'location': {
                    'city': row_data.get('Company City', '').strip(),
                    'state': row_data.get('Company State', '').strip(),
                    'country': row_data.get('Company Country', '').strip()
                },
                'funding': {
                    'total_funding': row_data.get('Total Funding', '').strip(),
                    'latest_funding': row_data.get('Latest Funding', '').strip(),
                    'latest_amount': row_data.get('Latest Funding Amount', '').strip()
                }
            }
        }
        
        # Remove empty fields
        enriched['apollo_data'] = {k: v for k, v in enriched['apollo_data'].items() 
                                 if v not in ['', None, [], {}]}
        
        return enriched
    
    def parse_csv_file(self, file_path: str) -> Tuple[List[Dict], List[str], Dict]:
        """Parse Apollo CSV file and return scanner-compatible data"""
        logger.info(f"Parsing Apollo CSV file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Detect delimiter
                sample = file.read(1024)
                file.seek(0)
                delimiter = ',' if sample.count(',') > sample.count(';') else ';'
                
                reader = csv.DictReader(file, delimiter=delimiter)
                
                for row_num, row in enumerate(reader, 1):
                    self.stats['total_rows'] += 1
                    
                    # Extract required fields
                    company_name = row.get('Company', '').strip()
                    website = row.get('Website', '').strip()
                    
                    if not company_name:
                        self.errors.append(f"Row {row_num}: Missing company name")
                        continue
                    
                    if not website:
                        self.errors.append(f"Row {row_num}: Missing website for {company_name}")
                        self.stats['missing_websites'] += 1
                        continue
                    
                    # Clean domain
                    domain = self.clean_domain(website)
                    if not domain:
                        self.errors.append(f"Row {row_num}: Invalid domain '{website}' for {company_name}")
                        self.stats['invalid_domains'] += 1
                        continue
                    
                    # Create scanner-compatible entry
                    scanner_entry = {
                        'domain': domain,
                        'company_name': company_name,
                        'contact_email': '',  # Apollo doesn't include direct emails
                        'priority': self.determine_priority(row),
                        'source': 'apollo',
                        'original_website': website
                    }
                    
                    # Add enriched data
                    enriched_data = self.enrich_company_data(row)
                    scanner_entry.update(enriched_data)
                    
                    self.parsed_data.append(scanner_entry)
                    self.stats['valid_companies'] += 1
                    self.stats['enriched_data'] += 1
                    
                    logger.debug(f"Parsed company: {company_name} -> {domain}")
        
        except Exception as e:
            error_msg = f"Error parsing Apollo CSV: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
        
        logger.info(f"Apollo parsing completed: {self.stats['valid_companies']}/{self.stats['total_rows']} companies processed")
        return self.parsed_data, self.errors, self.stats
    
    def convert_to_scanner_csv(self, output_path: str) -> bool:
        """Convert parsed Apollo data to scanner-compatible CSV format"""
        if not self.parsed_data:
            return False
            
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                
                # Write header
                writer.writerow(['domain', 'company_name', 'contact_email', 'priority'])
                
                # Write data
                for entry in self.parsed_data:
                    writer.writerow([
                        entry['domain'],
                        entry['company_name'],
                        entry.get('contact_email', ''),
                        entry['priority']
                    ])
            
            logger.info(f"Scanner-compatible CSV created: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating scanner CSV: {str(e)}")
            return False
    
    def save_enriched_data(self, output_path: str) -> bool:
        """Save enriched Apollo data as JSON for future reference"""
        if not self.parsed_data:
            return False
            
        try:
            enriched_export = {
                'metadata': {
                    'source': 'apollo.io',
                    'total_companies': len(self.parsed_data),
                    'parsing_stats': self.stats,
                    'parsing_errors': self.errors
                },
                'companies': self.parsed_data
            }
            
            with open(output_path, 'w', encoding='utf-8') as file:
                json.dump(enriched_export, file, indent=2, ensure_ascii=False)
            
            logger.info(f"Enriched Apollo data saved: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving enriched data: {str(e)}")
            return False

def parse_apollo_file(file_path: str, output_csv: str = None, output_json: str = None) -> Dict:
    """
    Main function to parse Apollo CSV file
    
    Args:
        file_path: Path to Apollo CSV file
        output_csv: Optional path for scanner-compatible CSV output
        output_json: Optional path for enriched JSON output
    
    Returns:
        Dictionary with parsing results
    """
    parser = ApolloParser()
    data, errors, stats = parser.parse_csv_file(file_path)
    
    results = {
        'success': len(data) > 0,
        'data': data,
        'errors': errors,
        'stats': stats,
        'csv_created': False,
        'json_created': False
    }
    
    # Create scanner-compatible CSV if requested
    if output_csv and data:
        results['csv_created'] = parser.convert_to_scanner_csv(output_csv)
    
    # Save enriched data if requested
    if output_json and data:
        results['json_created'] = parser.save_enriched_data(output_json)
    
    return results

if __name__ == "__main__":
    # Example usage
    results = parse_apollo_file(
        "apollo_companies.csv",
        output_csv="apollo_scanner_format.csv",
        output_json="apollo_enriched_data.json"
    )
    
    print(f"Parsing results: {results['stats']}")
    if results['errors']:
        print(f"Errors encountered: {len(results['errors'])}") 