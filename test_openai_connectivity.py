#!/usr/bin/env python3
"""
OpenAI Connectivity Test for Cyber Insurance Scanner
Tests OpenAI API connection and configuration
"""

import os
import asyncio
import logging
from pathlib import Path
from typing import Optional

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OpenAIConnectivityTest:
    """Test OpenAI connectivity and configuration"""
    
    def __init__(self):
        self.client = None
        self.test_results = {
            "environment_variables": False,
            "openai_library": False,
            "api_connection": False,
            "model_access": False,
            "test_generation": False
        }
    
    def test_environment_variables(self) -> bool:
        """Test if environment variables are properly loaded"""
        logger.info("🔍 Testing environment variable loading...")
        
        # Check if .env file exists
        env_file = Path(".env")
        if env_file.exists():
            logger.info(f"✅ Found .env file: {env_file.absolute()}")
        else:
            logger.warning("⚠️  No .env file found - using environment variables or defaults")
        
        # Check OpenAI configuration
        api_key = settings.openai_api_key or os.getenv("OPENAI_API_KEY", "")
        model = settings.openai_model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        enabled = settings.openai_enabled or os.getenv("OPENAI_ENABLED", "false").lower() == "true"
        
        logger.info(f"📋 OpenAI Configuration:")
        logger.info(f"   API Key: {'✅ Set' if api_key.strip() else '❌ Missing'}")
        logger.info(f"   Model: {model}")
        logger.info(f"   Enabled: {enabled}")
        logger.info(f"   Enhanced Reports: {settings.enhanced_reports_enabled}")
        
        if not api_key.strip():
            logger.error("❌ OpenAI API key is missing!")
            logger.info("💡 To fix this, add to .env file:")
            logger.info("   OPENAI_API_KEY=your-api-key-here")
            logger.info("   OPENAI_MODEL=gpt-4o-mini")
            logger.info("   OPENAI_ENABLED=true")
            return False
        
        self.test_results["environment_variables"] = True
        return True
    
    def test_openai_library(self) -> bool:
        """Test if OpenAI library is available"""
        logger.info("🔍 Testing OpenAI library installation...")
        
        if not OPENAI_AVAILABLE:
            logger.error("❌ OpenAI library not installed!")
            logger.info("💡 To fix this, run: pip install openai>=1.12.0")
            return False
        
        logger.info("✅ OpenAI library is available")
        self.test_results["openai_library"] = True
        return True
    
    def test_api_connection(self) -> bool:
        """Test basic API connection"""
        logger.info("🔍 Testing OpenAI API connection...")
        
        try:
            api_key = settings.openai_api_key or os.getenv("OPENAI_API_KEY", "")
            if not api_key.strip():
                logger.error("❌ No API key available for testing")
                return False
            
            self.client = OpenAI(api_key=api_key)
            
            # Test basic connection with a simple API call
            models = self.client.models.list()
            logger.info("✅ Successfully connected to OpenAI API")
            logger.info(f"📊 Available models: {len(models.data)} models found")
            
            self.test_results["api_connection"] = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to OpenAI API: {str(e)}")
            if "api_key" in str(e).lower():
                logger.info("💡 Check your API key is valid and has sufficient credits")
            return False
    
    def test_model_access(self) -> bool:
        """Test access to the configured model"""
        logger.info("🔍 Testing access to configured model...")
        
        if not self.client:
            logger.error("❌ No API client available")
            return False
        
        try:
            model = settings.openai_model or "gpt-4o-mini"
            
            # Test model access with a simple completion
            response = self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=5
            )
            
            logger.info(f"✅ Successfully accessed model: {model}")
            logger.info(f"📝 Test response: {response.choices[0].message.content}")
            
            self.test_results["model_access"] = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to access model {model}: {str(e)}")
            if "model" in str(e).lower():
                logger.info("💡 Try using 'gpt-4o-mini' or 'gpt-3.5-turbo' as the model")
            return False
    
    def test_report_generation(self) -> bool:
        """Test report generation capabilities"""
        logger.info("🔍 Testing report generation...")
        
        if not self.client:
            logger.error("❌ No API client available")
            return False
        
        try:
            model = settings.openai_model or "gpt-4o-mini"
            
            # Test with a sample security report prompt
            prompt = """Generate a brief security assessment summary for a test company:
            Company: Test Corp
            Risk Score: 75/100
            Vulnerabilities: 5 high, 10 medium
            
            Provide a 2-sentence executive summary."""
            
            response = self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100
            )
            
            generated_text = response.choices[0].message.content
            logger.info("✅ Successfully generated test report")
            logger.info(f"📄 Sample output: {generated_text[:100]}...")
            
            self.test_results["test_generation"] = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to generate test report: {str(e)}")
            return False
    
    def run_full_test(self) -> dict:
        """Run all connectivity tests"""
        logger.info("🚀 Starting OpenAI Connectivity Test Suite")
        logger.info("=" * 50)
        
        # Run all tests
        tests = [
            ("Environment Variables", self.test_environment_variables),
            ("OpenAI Library", self.test_openai_library),
            ("API Connection", self.test_api_connection),
            ("Model Access", self.test_model_access),
            ("Report Generation", self.test_report_generation)
        ]
        
        for test_name, test_func in tests:
            logger.info(f"\n🧪 Running: {test_name}")
            success = test_func()
            if not success and test_name in ["Environment Variables", "OpenAI Library"]:
                # Stop early if critical tests fail
                break
        
        # Summary
        logger.info("\n" + "=" * 50)
        logger.info("📊 TEST RESULTS SUMMARY")
        logger.info("=" * 50)
        
        passed = sum(self.test_results.values())
        total = len(self.test_results)
        
        for test, result in self.test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            logger.info(f"   {test.replace('_', ' ').title()}: {status}")
        
        logger.info(f"\n🎯 Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            logger.info("🎉 All tests passed! OpenAI integration is ready.")
        elif passed >= 3:
            logger.warning("⚠️  Partial functionality available - some features may not work")
        else:
            logger.error("❌ OpenAI integration not working - enhanced reports will be disabled")
        
        return self.test_results


def main():
    """Main test runner"""
    print("🔧 Cyber Insurance Scanner - OpenAI Connectivity Test")
    print("=" * 60)
    
    tester = OpenAIConnectivityTest()
    results = tester.run_full_test()
    
    # Return exit code based on results
    passed = sum(results.values())
    total = len(results)
    
    if passed == total:
        exit(0)  # All tests passed
    elif passed >= 3:
        exit(1)  # Partial functionality
    else:
        exit(2)  # Major issues


if __name__ == "__main__":
    main() 