#!/usr/bin/env python3
"""
Example script demonstrating Cyber Insurance Scanner usage
"""
import asyncio
import json
from datetime import datetime
from pathlib import Path

from models import Lead, ScanRequest
from modules.scanner_orchestrator import ScannerOrchestrator


async def single_domain_example():
    """Example: Scan a single domain"""
    print("=== Single Domain Scan Example ===")
    
    # Create a lead
    lead = Lead(
        domain="example.com",
        company_name="Example Corporation"
    )
    
    # Initialize scanner
    scanner = ScannerOrchestrator()
    
    # Perform quick scan
    print(f"Starting quick scan for {lead.domain}...")
    result = await scanner.quick_scan(lead)
    
    if result and result.risk_score:
        print(f"✓ Scan completed!")
        print(f"  Risk Score: {result.risk_score.overall_score:.1f}/100")
        print(f"  Risk Category: {result.risk_score.risk_category.upper()}")
        print(f"  Assets Found: {len(result.assets)}")
        print(f"  Open Ports: {result.risk_score.total_open_ports}")
        print(f"  Vulnerabilities: {result.risk_score.total_vulnerabilities}")
        
        # Show high-risk ports if any
        if result.risk_score.high_risk_ports:
            print(f"  ⚠️  High-Risk Ports: {result.risk_score.high_risk_ports}")
    else:
        print("✗ Scan failed or no results")
    
    print()


async def batch_scan_example():
    """Example: Scan multiple domains"""
    print("=== Batch Scan Example ===")
    
    # Create multiple leads
    leads = [
        Lead(domain="example.com", company_name="Example Corp"),
        Lead(domain="google.com", company_name="Google Inc"),
        Lead(domain="github.com", company_name="GitHub Inc"),
    ]
    
    # Create scan request
    scan_request = ScanRequest(
        leads=leads,
        scan_type="quick",
        include_subdomains=False,  # Faster for demo
        include_vulnerability_scan=True
    )
    
    # Initialize scanner
    scanner = ScannerOrchestrator()
    
    print(f"Starting batch scan for {len(leads)} domains...")
    results = await scanner.execute_scan(scan_request)
    
    print(f"✓ Batch scan completed! Results for {len(results)} domains:")
    
    for result in results:
        if result.scan_status == "completed" and result.risk_score:
            risk_color = get_risk_emoji(result.risk_score.risk_category)
            print(f"  {risk_color} {result.lead.domain}: {result.risk_score.overall_score:.1f} ({result.risk_score.risk_category})")
        else:
            print(f"  ❌ {result.lead.domain}: Scan failed - {result.error_message or 'Unknown error'}")
    
    # Generate summary
    analysis = scanner.analyze_scan_results(results)
    print(f"\n📊 Summary:")
    print(f"  Total scans: {analysis.get('total_scans', 0)}")
    print(f"  Successful: {analysis.get('completed_scans', 0)}")
    print(f"  Failed: {analysis.get('failed_scans', 0)}")
    print(f"  Average scan time: {analysis.get('avg_scan_duration', 0):.1f}s")
    
    print()


async def comprehensive_scan_example():
    """Example: Comprehensive scan with full analysis"""
    print("=== Comprehensive Scan Example ===")
    
    # Create lead for a test domain
    lead = Lead(
        domain="scanme.nmap.org",  # A safe domain for testing
        company_name="Nmap Test Domain"
    )
    
    scanner = ScannerOrchestrator()
    
    print(f"Starting comprehensive scan for {lead.domain}...")
    print("This may take several minutes...")
    
    # Perform full scan
    result = await scanner.full_scan(lead)
    
    if result and result.scan_status == "completed":
        print(f"✓ Comprehensive scan completed!")
        
        # Display detailed results
        print(f"\n📋 Scan Results for {lead.domain}:")
        print(f"  Company: {lead.company_name}")
        print(f"  Scan Duration: {result.scan_duration:.1f}s")
        
        if result.risk_score:
            print(f"\n🎯 Risk Assessment:")
            print(f"  Overall Score: {result.risk_score.overall_score:.1f}/100")
            print(f"  Risk Category: {result.risk_score.risk_category.upper()}")
            print(f"  Port Risk: {result.risk_score.port_risk_score:.1f}")
            print(f"  Vulnerability Risk: {result.risk_score.vulnerability_risk_score:.1f}")
            print(f"  SSL Risk: {result.risk_score.ssl_risk_score:.1f}")
            print(f"  Service Risk: {result.risk_score.service_risk_score:.1f}")
        
        print(f"\n🔍 Discovery Results:")
        print(f"  Assets Found: {len(result.assets)}")
        print(f"  Open Ports: {len([p for p in result.port_scan_results if p.state == 'open'])}")
        print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
        
        # Show assets
        if result.assets:
            print(f"\n🌐 Discovered Assets:")
            for asset in result.assets[:5]:  # Show first 5
                print(f"    • {asset.subdomain}:{asset.port} ({asset.protocol.upper()})")
                if asset.title:
                    print(f"      Title: {asset.title[:60]}...")
                if asset.tech_stack:
                    print(f"      Tech: {', '.join(asset.tech_stack)}")
        
        # Show open ports
        open_ports = [p for p in result.port_scan_results if p.state == 'open']
        if open_ports:
            print(f"\n🔓 Open Ports:")
            for port in open_ports[:10]:  # Show first 10
                service_info = f" ({port.service})" if port.service else ""
                version_info = f" {port.version}" if port.version else ""
                print(f"    • {port.port}/{port.protocol}{service_info}{version_info}")
        
        # Show vulnerabilities
        if result.vulnerabilities:
            print(f"\n⚠️  Vulnerabilities:")
            severity_counts = {}
            for vuln in result.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
            for severity, count in severity_counts.items():
                emoji = get_severity_emoji(severity)
                print(f"    {emoji} {severity}: {count}")
            
            # Show top 3 vulnerabilities
            sorted_vulns = sorted(result.vulnerabilities, key=lambda v: v.cvss_score, reverse=True)
            for vuln in sorted_vulns[:3]:
                print(f"    • {vuln.cve_id} (CVSS: {vuln.cvss_score})")
                print(f"      {vuln.description[:80]}...")
        
        # Save results
        save_results(result)
        
    else:
        print(f"✗ Scan failed: {result.error_message if result else 'Unknown error'}")
    
    print()


def save_results(scan_result):
    """Save scan results to file"""
    # Create results directory
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{scan_result.lead.domain}_{timestamp}.json"
    filepath = results_dir / filename
    
    # Save to JSON
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(scan_result.dict(), f, indent=2, default=str)
    
    print(f"📁 Results saved to: {filepath}")


def get_risk_emoji(risk_category: str) -> str:
    """Get emoji for risk category"""
    emojis = {
        'low': '🟢',
        'medium': '🟡', 
        'high': '🟠',
        'critical': '🔴'
    }
    return emojis.get(risk_category.lower(), '❓')


def get_severity_emoji(severity: str) -> str:
    """Get emoji for vulnerability severity"""
    emojis = {
        'LOW': '🟢',
        'MEDIUM': '🟡',
        'HIGH': '🟠', 
        'CRITICAL': '🔴'
    }
    return emojis.get(severity.upper(), '❓')


async def main():
    """Main example function"""
    print("🔒 Cyber Insurance Scanner - Example Usage")
    print("=" * 50)
    print()
    
    try:
        # Run examples
        await single_domain_example()
        await batch_scan_example()
        
        # Ask user if they want to run comprehensive scan
        response = input("Run comprehensive scan example? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            await comprehensive_scan_example()
        
        print("✨ All examples completed!")
        
    except KeyboardInterrupt:
        print("\n🛑 Examples interrupted by user")
    except Exception as e:
        print(f"❌ Error running examples: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the examples
    asyncio.run(main()) 