#!/usr/bin/env python3
"""
Environment Setup Script for Cyber Insurance Scanner
Helps users configure their environment variables properly
"""

import os
import sys
from pathlib import Path

def create_env_file():
    """Create a .env file with default configuration"""
    env_content = """# Cyber Insurance Scanner Environment Configuration
# Update these values with your actual configuration

# ===================================
# OpenAI Configuration (for AI Reports)
# ===================================
# Get your API key from: https://platform.openai.com/api-keys
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_ENABLED=true

# ===================================
# Application Settings
# ===================================
APP_NAME=Cyber Insurance Scanner
APP_VERSION=1.0.0
DEBUG=false

# ===================================
# API Configuration
# ===================================
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=1

# ===================================
# Security Settings
# ===================================
SECRET_KEY=change-this-secret-key-in-production
API_KEY=change-this-api-key-in-production
REQUIRE_AUTH=false

# ===================================
# Scanning Performance
# ===================================
MAX_CONCURRENT_SCANS=15
SCAN_TIMEOUT=300
NMAP_TIMEOUT=120
SUBDOMAIN_TIMEOUT=180

# DNS and HTTP concurrency settings
DNS_CONCURRENCY=150
HTTP_CONCURRENCY=90
ASSET_DISCOVERY_TIMEOUT=3

# ===================================
# File Paths
# ===================================
UPLOAD_DIR=./uploads
REPORT_DIR=./reports
LOG_DIR=./logs

# ===================================
# Risk Scoring Weights (sum must = 1.0)
# ===================================
PORT_RISK_WEIGHT=0.3
VULNERABILITY_RISK_WEIGHT=0.5
SSL_RISK_WEIGHT=0.1
SERVICE_RISK_WEIGHT=0.1
"""
    
    env_file = Path(".env")
    
    if env_file.exists():
        print(f"⚠️  .env file already exists at {env_file.absolute()}")
        response = input("Do you want to overwrite it? (y/N): ").lower().strip()
        if response != 'y':
            print("❌ Setup cancelled")
            return False
    
    try:
        with open(env_file, 'w') as f:
            f.write(env_content)
        print(f"✅ Created .env file at {env_file.absolute()}")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'fastapi',
        'uvicorn', 
        'openai',
        'python-nmap',
        'dnspython',
        'httpx',
        'weasyprint'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing.append(package)
    
    if missing:
        print(f"\n🚨 Missing dependencies: {', '.join(missing)}")
        print("💡 Install them with: pip install -r requirements.txt")
        return False
    else:
        print("✅ All dependencies are installed")
        return True

def setup_openai():
    """Interactive OpenAI setup"""
    print("\n🤖 OpenAI Setup")
    print("=" * 30)
    
    print("To enable AI-enhanced reports, you need an OpenAI API key.")
    print("Get one from: https://platform.openai.com/api-keys")
    
    api_key = input("\nEnter your OpenAI API key (or press Enter to skip): ").strip()
    
    if not api_key:
        print("⏭️  Skipping OpenAI setup - enhanced reports will be disabled")
        return
    
    # Update .env file with API key
    env_file = Path(".env")
    if env_file.exists():
        try:
            with open(env_file, 'r') as f:
                content = f.read()
            
            # Replace the placeholder API key
            content = content.replace('OPENAI_API_KEY=your-openai-api-key-here', f'OPENAI_API_KEY={api_key}')
            
            with open(env_file, 'w') as f:
                f.write(content)
            
            print("✅ Updated .env file with your OpenAI API key")
            
            # Test the API key
            print("🧪 Testing OpenAI connection...")
            os.system("python3 test_openai_connectivity.py")
            
        except Exception as e:
            print(f"❌ Failed to update .env file: {e}")
    else:
        print("❌ No .env file found to update")

def main():
    """Main setup function"""
    print("🔧 Cyber Insurance Scanner - Environment Setup")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("api.py").exists():
        print("❌ Please run this script from the scanner project directory")
        sys.exit(1)
    
    # Step 1: Check dependencies
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n❌ Please install missing dependencies first")
        sys.exit(1)
    
    # Step 2: Create .env file
    print("\n📝 Setting up environment file...")
    env_created = create_env_file()
    
    if env_created:
        # Step 3: Setup OpenAI
        setup_openai()
        
        print("\n🎉 Setup Complete!")
        print("=" * 50)
        print("✅ Environment file created")
        print("💡 Next steps:")
        print("   1. Review and update .env file with your settings")
        print("   2. Start the server with: python3 api.py")
        print("   3. Test OpenAI connectivity: python3 test_openai_connectivity.py")
        
    else:
        print("\n❌ Setup failed - could not create environment file")

if __name__ == "__main__":
    main() 