#!/usr/bin/env python3
"""
ServiceNow CMDB Compliance Scanner - Demo Script
"""

import os
import sys
from compliance_analyzer import demo_compliance_analysis
from network_scanner import demo_network_scanning

def print_banner():
    """Print demo banner"""
    print("=" * 80)
    print("🔍 ServiceNow CMDB Compliance Scanner - DEMO")
    print("   Demonstrating compliance analysis capabilities")
    print("=" * 80)
    print()

def demo_compliance_features():
    """Demonstrate core compliance analysis features"""
    print("📊 DEMO: Compliance Analysis Features")
    print("-" * 50)
    
    # Run compliance analysis demo
    demo_compliance_analysis()
    
    print("\n✅ Compliance analysis demo completed!")
    print("📄 Check generated files for detailed results")

def demo_network_features():
    """Demonstrate network scanning features"""
    print("\n🔍 DEMO: Network Scanning Features")
    print("-" * 50)
    
    # Run network scanning demo
    demo_network_scanning()
    
    print("\n✅ Network scanning demo completed!")

def demo_integration():
    """Demonstrate end-to-end integration"""
    print("\n🔄 DEMO: Integration Test")
    print("-" * 50)
    
    from servicenow_connector import ServiceNowConnector
    from network_scanner import NetworkOSScanner
    from compliance_analyzer import ComplianceAnalyzer
    
    # Sample CI data for integration test
    sample_cis = [
        {
            'name': 'demo-server-01',
            'ip_address': '8.8.8.8',  # Google DNS for demo
            'os_name': 'Unknown',
            'os_version': ''
        }
    ]
    
    try:
        print("1. Testing network scanner...")
        scanner = NetworkOSScanner(max_threads=1)
        scan_results = scanner.scan_ci_list(sample_cis)
        print(f"   ✅ Scanned {len(scan_results)} targets")
        
        print("2. Testing compliance analyzer...")
        analyzer = ComplianceAnalyzer()
        compliance_report = analyzer.analyze_ci_list(scan_results)
        print(f"   ✅ Analyzed {compliance_report['summary_statistics']['total_systems']} systems")
        
        print("3. Exporting results...")
        analyzer.export_compliance_report(compliance_report, "integration_demo")
        print("   ✅ Results exported")
        
        print("\n📊 Integration Test Summary:")
        stats = compliance_report['summary_statistics']
        print(f"   Total Systems: {stats['total_systems']}")
        print(f"   Compliance Score: {compliance_report['compliance_score']}%")
        
    except Exception as e:
        print(f"   ❌ Integration test failed: {e}")

def demo_web_interface_info():
    """Show web interface information"""
    print("\n🌐 WEB INTERFACE DEMO")
    print("-" * 50)
    print("To test the web interface:")
    print("1. Run: python web_interface.py")
    print("2. Open: http://localhost:8000")
    print("3. Use the 'Demo' mode for testing without ServiceNow")
    print("4. View API documentation at: http://localhost:8000/docs")

def demo_main_script_info():
    """Show main script usage information"""
    print("\n🚀 MAIN SCRIPT DEMO")
    print("-" * 50)
    print("Command line usage examples:")
    print("1. Demo mode:       python main.py --mode demo")
    print("2. Check environment: python main.py --check-env")
    print("3. Standalone mode: python main.py --mode standalone --scope all")
    print("4. CrewAI mode:     python main.py --mode crewai --scope servers")

def main():
    """Main demo function"""
    print_banner()
    
    print("🎯 Available Demo Options:")
    print("1. Compliance Analysis Features")
    print("2. Network Scanning Features") 
    print("3. Integration Test")
    print("4. Web Interface Info")
    print("5. Main Script Usage")
    print("6. Run All Demos")
    print()
    
    try:
        choice = input("Select demo option (1-6): ").strip()
        
        if choice == "1":
            demo_compliance_features()
        elif choice == "2":
            demo_network_features()
        elif choice == "3":
            demo_integration()
        elif choice == "4":
            demo_web_interface_info()
        elif choice == "5":
            demo_main_script_info()
        elif choice == "6":
            demo_compliance_features()
            demo_network_features()
            demo_integration()
            demo_web_interface_info()
            demo_main_script_info()
        else:
            print("Invalid choice. Running compliance analysis demo...")
            demo_compliance_features()
            
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
    
    print("\n🎉 Demo session completed!")
    print("📁 Check the current directory for generated output files")

if __name__ == "__main__":
    main()