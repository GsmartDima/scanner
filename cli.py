"""
Command Line Interface for Cyber Insurance Scanner
Provides CLI access to all scanning functionality
"""
import asyncio
import click
import json
import csv
import sys
from pathlib import Path
from datetime import datetime
from typing import List
import logging

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from config import settings
from models import Lead, ScanRequest
from modules.lead_input import LeadInputProcessor
from modules.scanner_orchestrator import ScannerOrchestrator

# Initialize components
console = Console()
lead_processor = LeadInputProcessor()
scanner = ScannerOrchestrator()

# Configure logging for CLI
logging.basicConfig(level=logging.WARNING)


@click.group()
@click.version_option(version=settings.app_version)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def cli(verbose):
    """
    Cyber Insurance Scanner CLI
    
    Automated cybersecurity risk assessment tool for insurance companies.
    """
    if verbose:
        logging.basicConfig(level=logging.INFO)


@cli.command()
@click.argument('domain')
@click.option('--company', '-c', help='Company name')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'csv']), default='json', help='Output format')
def quick_scan(domain: str, company: str, output: str, output_format: str):
    """Perform a quick security scan on a domain"""
    async def run_scan():
        lead = Lead(
            domain=domain,
            company_name=company or f"Company for {domain}"
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task(f"Scanning {domain}...", total=None)
            
            try:
                result = await scanner.quick_scan(lead)
                progress.update(task, description=f"Scan completed for {domain}")
                
                if result:
                    display_scan_result(result)
                    
                    if output:
                        save_result(result, output, output_format)
                        console.print(f"[green]✓[/green] Results saved to {output}")
                else:
                    console.print("[red]✗[/red] Scan failed")
                    
            except Exception as e:
                progress.update(task, description=f"Scan failed: {str(e)}")
                console.print(f"[red]✗[/red] Error: {str(e)}")
                sys.exit(1)
    
    asyncio.run(run_scan())


@cli.command()
@click.argument('domain')
@click.option('--company', '-c', help='Company name')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'csv']), default='json', help='Output format')
@click.option('--max-subdomains', type=int, default=50, help='Maximum number of subdomains to discover')
def full_scan(domain: str, company: str, output: str, output_format: str, max_subdomains: int):
    """Perform a comprehensive security scan on a domain"""
    async def run_scan():
        lead = Lead(
            domain=domain,
            company_name=company or f"Company for {domain}"
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task(f"Full scan of {domain}...", total=None)
            
            try:
                result = await scanner.full_scan(lead)
                progress.update(task, description=f"Full scan completed for {domain}")
                
                if result:
                    display_scan_result(result)
                    
                    if output:
                        save_result(result, output, output_format)
                        console.print(f"[green]✓[/green] Results saved to {output}")
                else:
                    console.print("[red]✗[/red] Scan failed")
                    
            except Exception as e:
                progress.update(task, description=f"Scan failed: {str(e)}")
                console.print(f"[red]✗[/red] Error: {str(e)}")
                sys.exit(1)
    
    asyncio.run(run_scan())


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for results')
@click.option('--scan-type', type=click.Choice(['quick', 'full']), default='quick', help='Type of scan to perform')
@click.option('--max-concurrent', type=int, default=3, help='Maximum concurrent scans')
def batch_scan(file_path: str, output: str, scan_type: str, max_concurrent: int):
    """Perform batch scanning from a CSV/JSON file"""
    async def run_batch():
        try:
            # Process the input file
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                load_task = progress.add_task("Loading leads...", total=None)
                
                # Load leads from file
                file_path_obj = Path(file_path)
                leads = []
                
                if file_path_obj.suffix.lower() == '.csv':
                    leads = load_leads_from_csv(file_path)
                elif file_path_obj.suffix.lower() == '.json':
                    leads = load_leads_from_json(file_path)
                else:
                    console.print("[red]✗[/red] Unsupported file format. Use CSV or JSON.")
                    sys.exit(1)
                
                progress.update(load_task, description=f"Loaded {len(leads)} leads")
                
                if not leads:
                    console.print("[red]✗[/red] No valid leads found in file")
                    sys.exit(1)
                
                # Create scan request
                scan_request = ScanRequest(
                    leads=leads,
                    scan_type=scan_type,
                    include_subdomains=(scan_type == 'full'),
                    include_vulnerability_scan=(scan_type == 'full')
                )
                
                # Limit concurrency
                original_limit = settings.max_concurrent_scans
                settings.max_concurrent_scans = max_concurrent
                
                try:
                    scan_task = progress.add_task(f"Scanning {len(leads)} domains...", total=len(leads))
                    
                    results = await scanner.execute_scan(scan_request)
                    
                    progress.update(scan_task, completed=len(results), description="Batch scan completed")
                    
                    # Display summary
                    display_batch_summary(results)
                    
                    # Save results
                    if output:
                        save_batch_results(results, output)
                        console.print(f"[green]✓[/green] Results saved to {output}")
                    
                finally:
                    settings.max_concurrent_scans = original_limit
                    
        except Exception as e:
            console.print(f"[red]✗[/red] Batch scan failed: {str(e)}")
            sys.exit(1)
    
    asyncio.run(run_batch())


@cli.command()
@click.argument('results_file', type=click.Path(exists=True))
def analyze(results_file: str):
    """Analyze scan results and generate summary"""
    try:
        # Load results
        results = load_scan_results(results_file)
        
        if not results:
            console.print("[red]✗[/red] No results found in file")
            sys.exit(1)
        
        # Generate analysis
        analysis = scanner.analyze_scan_results(results)
        executive_summary = scanner.generate_executive_summary(results)
        
        # Display analysis
        display_analysis(analysis, executive_summary)
        
    except Exception as e:
        console.print(f"[red]✗[/red] Analysis failed: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option('--port', '-p', type=int, default=8000, help='Port to run server on')
@click.option('--host', '-h', default='0.0.0.0', help='Host to bind server to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def serve(port: int, host: str, reload: bool):
    """Start the web API server"""
    import uvicorn
    
    console.print(f"[green]Starting server on {host}:{port}[/green]")
    console.print(f"[blue]API docs available at: http://{host}:{port}/docs[/blue]")
    
    try:
        uvicorn.run(
            "api:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")


def load_leads_from_csv(file_path: str) -> List[Lead]:
    """Load leads from CSV file"""
    leads = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            try:
                lead = Lead(
                    domain=row.get('domain', '').strip(),
                    company_name=row.get('company_name', '').strip() or row.get('company', '').strip()
                )
                leads.append(lead)
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Skipping invalid row: {row} - {str(e)}")
    
    return leads


def load_leads_from_json(file_path: str) -> List[Lead]:
    """Load leads from JSON file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    leads = []
    
    if isinstance(data, list):
        for item in data:
            try:
                lead = Lead(**item)
                leads.append(lead)
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Skipping invalid lead: {item} - {str(e)}")
    
    return leads


def load_scan_results(file_path: str):
    """Load scan results from JSON file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Convert back to ScanResult objects would require more complex logic
    # For CLI analysis, work with the raw data
    return data


def display_scan_result(result):
    """Display scan result in a formatted table"""
    console.print()
    
    # Header panel
    if result.risk_score:
        risk_color = get_risk_color(result.risk_score.risk_category)
        header_text = f"[bold]{result.lead.domain}[/bold] - Risk Score: [{risk_color}]{result.risk_score.overall_score:.1f} ({result.risk_score.risk_category.upper()})[/{risk_color}]"
    else:
        header_text = f"[bold]{result.lead.domain}[/bold] - Scan Status: {result.scan_status}"
    
    console.print(Panel(header_text, title="Scan Results"))
    
    # Assets table
    if result.assets:
        assets_table = Table(title="Discovered Assets")
        assets_table.add_column("Subdomain")
        assets_table.add_column("IP Address")
        assets_table.add_column("Protocol")
        assets_table.add_column("Port")
        assets_table.add_column("Title")
        
        for asset in result.assets[:10]:  # Show first 10
            assets_table.add_row(
                asset.subdomain,
                asset.ip_address or "N/A",
                asset.protocol,
                str(asset.port),
                (asset.title or "")[:50] + ("..." if len(asset.title or "") > 50 else "")
            )
        
        console.print(assets_table)
        
        if len(result.assets) > 10:
            console.print(f"[dim]... and {len(result.assets) - 10} more assets[/dim]")
    
    # Open ports table
    open_ports = [p for p in result.port_scan_results if p.state == 'open']
    if open_ports:
        ports_table = Table(title="Open Ports")
        ports_table.add_column("IP Address")
        ports_table.add_column("Port")
        ports_table.add_column("Service")
        ports_table.add_column("Version")
        
        for port in open_ports[:15]:  # Show first 15
            ports_table.add_row(
                port.ip_address,
                str(port.port),
                port.service or "unknown",
                port.version or "N/A"
            )
        
        console.print(ports_table)
        
        if len(open_ports) > 15:
            console.print(f"[dim]... and {len(open_ports) - 15} more open ports[/dim]")
    
    # Vulnerabilities table
    if result.vulnerabilities:
        vuln_table = Table(title="Vulnerabilities")
        vuln_table.add_column("CVE ID")
        vuln_table.add_column("Severity")
        vuln_table.add_column("CVSS")
        vuln_table.add_column("Service")
        vuln_table.add_column("Description")
        
        for vuln in result.vulnerabilities[:10]:  # Show first 10
            severity_color = get_severity_color(vuln.severity)
            vuln_table.add_row(
                vuln.cve_id,
                f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                str(vuln.cvss_score),
                vuln.affected_service or "N/A",
                (vuln.description or "")[:60] + ("..." if len(vuln.description or "") > 60 else "")
            )
        
        console.print(vuln_table)
        
        if len(result.vulnerabilities) > 10:
            console.print(f"[dim]... and {len(result.vulnerabilities) - 10} more vulnerabilities[/dim]")
    
    console.print()


def display_batch_summary(results):
    """Display summary of batch scan results"""
    console.print()
    console.print(Panel("Batch Scan Summary", style="bold blue"))
    
    # Summary statistics
    total_scans = len(results)
    completed_scans = len([r for r in results if r.scan_status == "completed"])
    failed_scans = len([r for r in results if r.scan_status == "failed"])
    
    console.print(f"Total domains scanned: {total_scans}")
    console.print(f"Successful scans: [green]{completed_scans}[/green]")
    console.print(f"Failed scans: [red]{failed_scans}[/red]")
    
    # Risk distribution
    risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    high_risk_domains = []
    
    for result in results:
        if result.scan_status == "completed" and result.risk_score:
            category = result.risk_score.risk_category
            if category in risk_dist:
                risk_dist[category] += 1
            
            if result.risk_score.overall_score >= 75:
                high_risk_domains.append((result.lead.domain, result.risk_score.overall_score))
    
    console.print(f"\nRisk Distribution:")
    for category, count in risk_dist.items():
        if count > 0:
            color = get_risk_color(category)
            console.print(f"  [{color}]{category.title()}[/{color}]: {count}")
    
    # High-risk domains
    if high_risk_domains:
        console.print(f"\n[red]High-Risk Domains ({len(high_risk_domains)}):[/red]")
        high_risk_domains.sort(key=lambda x: x[1], reverse=True)
        for domain, score in high_risk_domains[:5]:
            console.print(f"  {domain}: {score:.1f}")
        
        if len(high_risk_domains) > 5:
            console.print(f"  ... and {len(high_risk_domains) - 5} more")
    
    console.print()


def display_analysis(analysis, executive_summary):
    """Display detailed analysis and executive summary"""
    console.print()
    console.print(Panel("Security Analysis Report", style="bold blue"))
    
    # Executive summary
    if executive_summary:
        summary = executive_summary
        
        console.print("[bold]Executive Summary[/bold]")
        console.print(f"• Total domains assessed: {summary['scan_overview']['total_domains_scanned']}")
        console.print(f"• Success rate: {summary['scan_overview']['success_rate_percentage']}%")
        console.print(f"• High-risk domains: {summary['risk_assessment']['high_risk_domains_count']}")
        console.print(f"• Total vulnerabilities: {summary['security_findings']['total_vulnerabilities']}")
        
        if summary['key_concerns']:
            console.print(f"\n[red]Key Concerns:[/red]")
            for concern in summary['key_concerns']:
                console.print(f"  • {concern}")
        
        if summary['recommendations']:
            console.print(f"\n[blue]Recommendations:[/blue]")
            for rec in summary['recommendations'][:5]:
                console.print(f"  • {rec}")
    
    console.print()


def save_result(result, output_path: str, format: str):
    """Save scan result to file"""
    try:
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(result.model_dump(), f, indent=2, default=str)
        elif format == 'csv':
            # Convert to CSV format
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow(['Domain', 'Company', 'Risk Score', 'Risk Category', 'Assets', 'Vulnerabilities', 'Open Ports'])
                
                # Data
                writer.writerow([
                    result.lead.domain,
                    result.lead.company_name,
                    result.risk_score.overall_score if result.risk_score else 'N/A',
                    result.risk_score.risk_category if result.risk_score else 'N/A',
                    len(result.assets),
                    len(result.vulnerabilities),
                    len([p for p in result.port_scan_results if p.state == 'open'])
                ])
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to save results: {str(e)}")


def save_batch_results(results, output_dir: str):
    """Save batch scan results"""
    try:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save individual results
        for result in results:
            filename = f"scan_{result.lead.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            file_path = output_path / filename
            
            with open(file_path, 'w') as f:
                json.dump(result.model_dump(), f, indent=2, default=str)
        
        # Save summary
        summary_path = output_path / "batch_summary.json"
        summary = {
            'total_scans': len(results),
            'successful_scans': len([r for r in results if r.scan_status == 'completed']),
            'scan_date': datetime.now().isoformat(),
            'results': [result.model_dump() for result in results]
        }
        
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        console.print(f"[green]✓[/green] Batch results saved to {output_dir}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to save batch results: {str(e)}")


def get_risk_color(risk_category: str) -> str:
    """Get color for risk category"""
    colors = {
        'low': 'green',
        'medium': 'yellow',
        'high': 'red',
        'critical': 'bright_red'
    }
    return colors.get(risk_category.lower(), 'white')


def get_severity_color(severity: str) -> str:
    """Get color for vulnerability severity"""
    colors = {
        'LOW': 'green',
        'MEDIUM': 'yellow',
        'HIGH': 'red',
        'CRITICAL': 'bright_red'
    }
    return colors.get(severity.upper(), 'white')


if __name__ == '__main__':
    cli() 