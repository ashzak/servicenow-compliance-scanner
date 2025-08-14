#!/usr/bin/env python3
"""
ServiceNow CMDB Compliance Scanner - Main Execution Script
"""

import argparse
import sys
import os
import json
from datetime import datetime
from servicenow_connector import ServiceNowConnector
from network_scanner import NetworkOSScanner
from compliance_analyzer import ComplianceAnalyzer

# Lazy import for CrewAI to avoid OpenAI API key requirement for demo
ComplianceScanningCrew = None

def print_banner():
    """Print application banner"""
    print("=" * 70)
    print("🔍 ServiceNow CMDB Compliance Scanner")
    print("   Multi-Agent Network OS Compliance Analysis")
    print("=" * 70)

def check_environment():
    """Check required environment variables and dependencies"""
    print("🔧 Checking environment setup...")
    
    # Check ServiceNow credentials
    required_env = ['SERVICENOW_INSTANCE', 'SERVICENOW_USERNAME', 'SERVICENOW_PASSWORD']
    missing_env = [var for var in required_env if not os.getenv(var)]
    
    if missing_env:
        print(f"❌ Missing environment variables: {', '.join(missing_env)}")
        print("\n💡 Setup Instructions:")
        print("export SERVICENOW_INSTANCE='your-instance.service-now.com'")
        print("export SERVICENOW_USERNAME='your-username'")
        print("export SERVICENOW_PASSWORD='your-password'")
        return False
    
    # Check OpenAI API key for CrewAI
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  OPENAI_API_KEY not set - CrewAI agents will not function")
        print("   Set OPENAI_API_KEY for full functionality")
    
    print("✅ Environment check completed")
    return True

def run_standalone_modules(target_scope="all"):
    """Run individual modules without CrewAI for testing"""
    print("🔧 Running standalone module tests...")
    results = {}
    
    try:
        # 1. Test ServiceNow connection
        print("\n📋 Testing ServiceNow CMDB connection...")
        connector = ServiceNowConnector()
        cis = connector.get_network_elements()
        results['servicenow'] = {
            'status': 'success',
            'ci_count': len(cis),
            'data': cis[:5] if cis else []  # Sample data
        }
        print(f"✅ ServiceNow: {len(cis)} CIs extracted")
        
        # 2. Test Network Scanner (limited sample)
        if cis:
            print("\n🔍 Testing network scanning...")
            scanner = NetworkOSScanner(max_threads=2)
            sample_cis = cis[:3]  # Test with first 3 CIs
            scan_results = scanner.scan_ci_list(sample_cis)
            results['scanning'] = {
                'status': 'success',
                'scanned_count': len(scan_results),
                'data': scan_results
            }
            print(f"✅ Network Scan: {len(scan_results)} targets scanned")
            
            # 3. Test Compliance Analysis
            print("\n📊 Testing compliance analysis...")
            analyzer = ComplianceAnalyzer()
            compliance_report = analyzer.analyze_ci_list(scan_results)
            results['compliance'] = {
                'status': 'success',
                'report': compliance_report
            }
            print(f"✅ Compliance Analysis: {compliance_report['summary_statistics']['total_systems']} systems analyzed")
            
            # Export results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"standalone_test_results_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"📄 Results exported to: {output_file}")
            
        else:
            print("❌ No CIs found for testing")
            
    except Exception as e:
        print(f"❌ Standalone test failed: {e}")
        results['error'] = str(e)
    
    return results

def run_crewai_workflow(target_scope="all"):
    """Run full CrewAI workflow"""
    print("🚀 Running CrewAI compliance scanning workflow...")
    
    try:
        # Lazy import CrewAI
        global ComplianceScanningCrew
        if ComplianceScanningCrew is None:
            from crew import ComplianceScanningCrew
        
        crew = ComplianceScanningCrew()
        result = crew.run_compliance_scan(target_scope)
        
        if result['success']:
            print(f"✅ CrewAI workflow completed successfully!")
            print(f"📁 Output directory: {result['output_directory']}")
            print(f"📊 Summary: {result['summary']}")
        else:
            print(f"❌ CrewAI workflow failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        print(f"❌ CrewAI execution failed: {e}")
        return {'success': False, 'error': str(e)}

def demo_compliance_analysis():
    """Run compliance analysis demo with sample data"""
    print("🔍 Running compliance analysis demo...")
    
    # Sample data for demo
    demo_cis = [
        {
            'ci_name': 'legacy-dc-server-01',
            'ip_address': '10.1.1.10',
            'detected_os': 'Windows Server 2008 R2',
            'detected_version': '2008 R2',
            'cmdb_os': 'Windows Server 2008 R2',
            'cmdb_version': '2008 R2'
        },
        {
            'ci_name': 'web-farm-02',
            'ip_address': '10.1.2.20',
            'detected_os': 'Ubuntu',
            'detected_version': '16.04',
            'cmdb_os': 'Ubuntu 16.04',
            'cmdb_version': '16.04'
        },
        {
            'ci_name': 'app-server-03',
            'ip_address': '10.1.3.30',
            'detected_os': 'Windows Server 2019',
            'detected_version': '2019',
            'cmdb_os': 'Windows Server 2019',
            'cmdb_version': '2019'
        },
        {
            'ci_name': 'legacy-centos-04',
            'ip_address': '10.1.4.40',
            'detected_os': 'CentOS',
            'detected_version': '6',
            'cmdb_os': 'CentOS 6',
            'cmdb_version': '6'
        }
    ]
    
    analyzer = ComplianceAnalyzer()
    compliance_report = analyzer.analyze_ci_list(demo_cis)
    
    # Export demo results
    analyzer.export_compliance_report(compliance_report, "demo_compliance_analysis")
    
    # Show summary
    stats = compliance_report['summary_statistics']
    print(f"\n📊 Demo Compliance Summary:")
    print(f"   Compliance Score: {compliance_report['compliance_score']}%")
    print(f"   Total Systems: {stats['total_systems']}")
    print(f"   Compliant: {stats['compliant']}")
    print(f"   Non-Compliant: {stats['non_compliant']}")
    print(f"   Critical Violations: {stats['critical_violations']}")
    print(f"   EOL Systems: {stats['eol_systems']}")
    
    return compliance_report

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='ServiceNow CMDB Compliance Scanner')
    parser.add_argument('--mode', choices=['crewai', 'standalone', 'demo'], 
                       default='demo', help='Execution mode')
    parser.add_argument('--scope', default='all', 
                       help='Target scope (all, servers, network)')
    parser.add_argument('--check-env', action='store_true',
                       help='Check environment setup only')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Environment check
    if args.check_env:
        check_environment()
        return
    
    # Execute based on mode
    if args.mode == 'demo':
        print("🎯 Running compliance analysis demo with sample data...")
        demo_compliance_analysis()
        
    elif args.mode == 'standalone':
        if not check_environment():
            sys.exit(1)
        print("🔧 Running standalone module tests...")
        run_standalone_modules(args.scope)
        
    elif args.mode == 'crewai':
        if not check_environment():
            sys.exit(1)
        if not os.getenv('OPENAI_API_KEY'):
            print("❌ OPENAI_API_KEY required for CrewAI mode")
            sys.exit(1)
        print("🤖 Running full CrewAI workflow...")
        run_crewai_workflow(args.scope)
    
    print("\n🎉 Execution completed!")
    print("📄 Check output files for detailed results")

if __name__ == "__main__":
    main()