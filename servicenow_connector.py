#!/usr/bin/env python3
"""
ServiceNow CMDB Integration Module
"""

import pysnow
import requests
import json
import os
from typing import Dict, List, Optional
from datetime import datetime

class ServiceNowConnector:
    """ServiceNow CMDB connection and data extraction"""
    
    def __init__(self, instance: str = None, username: str = None, password: str = None):
        """Initialize ServiceNow connection"""
        self.instance = instance or os.getenv('SERVICENOW_INSTANCE')
        self.username = username or os.getenv('SERVICENOW_USERNAME') 
        self.password = password or os.getenv('SERVICENOW_PASSWORD')
        
        if not all([self.instance, self.username, self.password]):
            raise ValueError("ServiceNow credentials not provided. Set SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD environment variables.")
        
        # Initialize pysnow client
        self.client = pysnow.Client(
            instance=self.instance,
            user=self.username,
            password=self.password
        )
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self):
        """Test ServiceNow connection"""
        try:
            # Simple test query
            resource = self.client.resource(api_path='/table/cmdb_ci')
            resource.parameters.add_query('sys_class_name', 'cmdb_ci_computer')
            resource.parameters.add_limit(1)
            list(resource.get_all())
            print("✅ ServiceNow connection successful")
        except Exception as e:
            print(f"❌ ServiceNow connection failed: {e}")
            raise
    
    def get_network_elements(self, ci_classes: List[str] = None) -> List[Dict]:
        """Extract network elements from CMDB"""
        
        if ci_classes is None:
            ci_classes = [
                'cmdb_ci_computer',      # Servers
                'cmdb_ci_linux_server',  # Linux servers
                'cmdb_ci_win_server',    # Windows servers  
                'cmdb_ci_unix_server',   # Unix servers
                'cmdb_ci_router',        # Routers
                'cmdb_ci_switch',        # Switches
                'cmdb_ci_firewall',      # Firewalls
                'cmdb_ci_load_balancer', # Load balancers
                'cmdb_ci_storage_switch' # Storage switches
            ]
        
        print(f"🔍 Extracting CIs from ServiceNow CMDB...")
        print(f"📋 Target CI Classes: {', '.join(ci_classes)}")
        
        all_cis = []
        
        for ci_class in ci_classes:
            print(f"   📊 Querying {ci_class}...")
            
            try:
                # Query specific CI class
                resource = self.client.resource(api_path='/table/cmdb_ci')
                resource.parameters.add_query('sys_class_name', ci_class)
                resource.parameters.add_query('operational_status', 'IN', '1,6')  # Operational, Authorized
                resource.parameters.add_encoded_query('ip_addressISNOTEMPTY')  # Has IP address
                
                # Select specific fields
                resource.parameters.add_fields([
                    'sys_id',
                    'name', 
                    'ip_address',
                    'fqdn',
                    'sys_class_name',
                    'operational_status',
                    'os',
                    'os_version',
                    'os_service_pack',
                    'discovery_source',
                    'last_discovered',
                    'assigned_to',
                    'managed_by',
                    'business_service',
                    'location',
                    'environment',
                    'install_status',
                    'sys_created_on',
                    'sys_updated_on'
                ])
                
                # Execute query
                cis = list(resource.get_all())
                
                # Process results
                for ci in cis:
                    ci_data = {
                        'sys_id': ci.get('sys_id', ''),
                        'name': ci.get('name', ''),
                        'ip_address': ci.get('ip_address', ''),
                        'fqdn': ci.get('fqdn', ''),
                        'ci_class': ci.get('sys_class_name', ''),
                        'operational_status': ci.get('operational_status', ''),
                        'os_name': ci.get('os', ''),
                        'os_version': ci.get('os_version', ''),
                        'os_service_pack': ci.get('os_service_pack', ''),
                        'discovery_source': ci.get('discovery_source', ''),
                        'last_discovered': ci.get('last_discovered', ''),
                        'assigned_to': ci.get('assigned_to', ''),
                        'managed_by': ci.get('managed_by', ''),
                        'business_service': ci.get('business_service', ''),
                        'location': ci.get('location', ''),
                        'environment': ci.get('environment', ''),
                        'install_status': ci.get('install_status', ''),
                        'created_date': ci.get('sys_created_on', ''),
                        'updated_date': ci.get('sys_updated_on', ''),
                        'cmdb_source': 'ServiceNow',
                        'extraction_timestamp': datetime.now().isoformat()
                    }
                    all_cis.append(ci_data)
                
                print(f"      ✅ Found {len(cis)} CIs in {ci_class}")
                
            except Exception as e:
                print(f"      ❌ Error querying {ci_class}: {e}")
                continue
        
        print(f"🎯 Total CIs extracted: {len(all_cis)}")
        return all_cis
    
    def get_ci_relationships(self, ci_sys_id: str) -> List[Dict]:
        """Get relationships for a specific CI"""
        
        try:
            resource = self.client.resource(api_path='/table/cmdb_rel_ci')
            resource.parameters.add_query('parent', ci_sys_id)
            resource.parameters.add_query('child', ci_sys_id)
            
            relationships = list(resource.get_all())
            
            rel_data = []
            for rel in relationships:
                rel_data.append({
                    'sys_id': rel.get('sys_id', ''),
                    'parent': rel.get('parent', ''),
                    'child': rel.get('child', ''),
                    'type': rel.get('type', ''),
                    'connection_strength': rel.get('connection_strength', '')
                })
            
            return rel_data
            
        except Exception as e:
            print(f"❌ Error getting relationships for {ci_sys_id}: {e}")
            return []
    
    def get_vulnerabilities(self, ci_sys_id: str) -> List[Dict]:
        """Get known vulnerabilities for a CI"""
        
        try:
            resource = self.client.resource(api_path='/table/sn_vul_vulnerable_item')
            resource.parameters.add_query('configuration_item', ci_sys_id)
            
            vulnerabilities = list(resource.get_all())
            
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append({
                    'sys_id': vuln.get('sys_id', ''),
                    'vulnerability': vuln.get('vulnerability', ''),
                    'state': vuln.get('state', ''),
                    'first_found': vuln.get('first_found', ''),
                    'last_found': vuln.get('last_found', ''),
                    'cve_id': vuln.get('cve_id', ''),
                    'cvss_score': vuln.get('cvss_score', ''),
                    'severity': vuln.get('severity', '')
                })
            
            return vuln_data
            
        except Exception as e:
            print(f"❌ Error getting vulnerabilities for {ci_sys_id}: {e}")
            return []
    
    def export_to_json(self, data: List[Dict], filename: str) -> str:
        """Export CI data to JSON file"""
        
        filepath = f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"📄 Data exported to: {filepath}")
        return filepath

# Demo/Test function
def demo_servicenow_extraction():
    """Demonstrate ServiceNow CMDB extraction"""
    
    print("🔍 ServiceNow CMDB Extraction Demo")
    print("=" * 50)
    
    try:
        # Initialize connector
        connector = ServiceNowConnector()
        
        # Extract network elements
        cis = connector.get_network_elements()
        
        if cis:
            # Export to JSON
            filepath = connector.export_to_json(cis, "cmdb_extraction")
            
            # Show summary
            print(f"\n📊 Extraction Summary:")
            print(f"   Total CIs: {len(cis)}")
            
            ci_classes = {}
            for ci in cis:
                ci_class = ci.get('ci_class', 'unknown')
                ci_classes[ci_class] = ci_classes.get(ci_class, 0) + 1
            
            for ci_class, count in ci_classes.items():
                print(f"   {ci_class}: {count}")
            
            print(f"   Output file: {filepath}")
            
        else:
            print("❌ No CIs found or extraction failed")
            
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        print("\n💡 Setup Instructions:")
        print("1. Set environment variables:")
        print("   export SERVICENOW_INSTANCE='your-instance.service-now.com'")
        print("   export SERVICENOW_USERNAME='your-username'") 
        print("   export SERVICENOW_PASSWORD='your-password'")
        print("2. Ensure ServiceNow account has CMDB read permissions")
        print("3. Test connection with demo script")

if __name__ == "__main__":
    demo_servicenow_extraction()