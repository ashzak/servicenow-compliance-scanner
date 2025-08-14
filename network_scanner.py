#!/usr/bin/env python3
"""
Network OS Detection and Scanning Module
"""

import nmap
import paramiko
import socket
import requests
import json
import re
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

class NetworkOSScanner:
    """Network OS detection and validation scanner"""
    
    def __init__(self, max_threads: int = 10, timeout: int = 30):
        self.max_threads = max_threads
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        self.scan_results = []
        
    def scan_target(self, target_ip: str, ci_data: Dict) -> Dict:
        """Comprehensive OS detection for a single target"""
        
        result = {
            'ip_address': target_ip,
            'ci_name': ci_data.get('name', ''),
            'cmdb_os': ci_data.get('os_name', ''),
            'cmdb_version': ci_data.get('os_version', ''),
            'scan_timestamp': datetime.now().isoformat(),
            'reachable': False,
            'detected_os': None,
            'detected_version': None,
            'confidence': 0,
            'scan_methods': [],
            'open_ports': [],
            'services': [],
            'errors': []
        }
        
        print(f"🔍 Scanning {target_ip} ({ci_data.get('name', 'Unknown')})")
        
        # 1. Basic connectivity check
        if not self._check_connectivity(target_ip):
            result['errors'].append("Target unreachable")
            return result
        
        result['reachable'] = True
        
        # 2. Nmap OS fingerprinting
        nmap_result = self._nmap_os_detection(target_ip)
        if nmap_result:
            result.update(nmap_result)
            result['scan_methods'].append('nmap')
        
        # 3. SSH banner grabbing
        ssh_result = self._ssh_banner_grab(target_ip)
        if ssh_result:
            result['detected_os'] = result.get('detected_os') or ssh_result.get('os')
            result['detected_version'] = result.get('detected_version') or ssh_result.get('version')
            result['scan_methods'].append('ssh')
        
        # 4. HTTP/HTTPS banner analysis
        http_result = self._http_banner_analysis(target_ip)
        if http_result:
            result['services'].extend(http_result.get('services', []))
            result['scan_methods'].append('http')
        
        # 5. SNMP system information
        snmp_result = self._snmp_system_info(target_ip)
        if snmp_result:
            result['detected_os'] = result.get('detected_os') or snmp_result.get('os')
            result['detected_version'] = result.get('detected_version') or snmp_result.get('version')
            result['scan_methods'].append('snmp')
        
        # 6. Validate against CMDB data
        result['cmdb_match'] = self._validate_cmdb_data(result, ci_data)
        
        return result
    
    def _check_connectivity(self, ip: str) -> bool:
        """Basic connectivity check using ping/socket"""
        try:
            socket.setdefaulttimeout(5)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 22))
            return True
        except:
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
                return True
            except:
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 443))
                    return True
                except:
                    return False
    
    def _nmap_os_detection(self, ip: str) -> Optional[Dict]:
        """Nmap OS fingerprinting"""
        try:
            # Nmap OS detection scan
            self.nm.scan(ip, arguments='-O -sS --max-retries 1 --host-timeout 30s')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                result = {
                    'open_ports': [],
                    'services': []
                }
                
                # Extract port information
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    for port in ports:
                        port_info = host_info[protocol][port]
                        if port_info['state'] == 'open':
                            result['open_ports'].append(f"{port}/{protocol}")
                            
                            service_info = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', ''),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            }
                            result['services'].append(service_info)
                
                # Extract OS information
                if 'osmatch' in host_info:
                    for osmatch in host_info['osmatch']:
                        if osmatch['accuracy'] > result.get('confidence', 0):
                            result['detected_os'] = osmatch['name']
                            result['confidence'] = int(osmatch['accuracy'])
                            
                            # Try to extract version from OS name
                            version_patterns = [
                                r'(\d+\.\d+\.\d+)',  # x.y.z
                                r'(\d+\.\d+)',       # x.y
                                r'(\d{4})',          # Year (Windows)
                                r'(Server \d{4})',   # Windows Server
                                r'(Ubuntu \d+\.\d+)', # Ubuntu version
                                r'(CentOS \d+)',     # CentOS version
                                r'(RHEL \d+)',       # RHEL version
                            ]
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, osmatch['name'])
                                if match:
                                    result['detected_version'] = match.group(1)
                                    break
                
                return result if result.get('detected_os') else None
                
        except Exception as e:
            print(f"   ❌ Nmap scan failed for {ip}: {e}")
            return None
    
    def _ssh_banner_grab(self, ip: str) -> Optional[Dict]:
        """SSH banner grabbing for OS detection"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Just connect to get banner, don't authenticate
            client.connect(
                ip, 
                port=22, 
                username='dummy', 
                password='dummy',
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
        except paramiko.AuthenticationException:
            # Expected - we just want the banner
            pass
        except Exception as e:
            # Try to extract banner from error message
            banner_text = str(e)
            
            # Extract OS information from SSH banner
            os_patterns = {
                'Ubuntu': r'Ubuntu[- ](\d+\.\d+)',
                'CentOS': r'CentOS[- ](\d+)',
                'RHEL': r'Red Hat Enterprise Linux[- ](\d+)',
                'Windows': r'Windows[- ](\w+)',
                'Cisco': r'Cisco[- ](\w+)',
                'Juniper': r'Juniper[- ](\w+)',
                'FreeBSD': r'FreeBSD[- ](\d+\.\d+)',
                'OpenBSD': r'OpenBSD[- ](\d+\.\d+)',
                'NetBSD': r'NetBSD[- ](\d+\.\d+)'
            }
            
            for os_name, pattern in os_patterns.items():
                match = re.search(pattern, banner_text, re.IGNORECASE)
                if match:
                    return {
                        'os': os_name,
                        'version': match.group(1) if match.groups() else None,
                        'banner': banner_text
                    }
        
        return None
    
    def _http_banner_analysis(self, ip: str) -> Optional[Dict]:
        """HTTP/HTTPS server banner analysis"""
        result = {'services': []}
        
        for port, protocol in [(80, 'HTTP'), (443, 'HTTPS')]:
            try:
                url = f"{'https' if port == 443 else 'http'}://{ip}:{port}"
                response = requests.get(url, timeout=10, verify=False)
                
                headers = response.headers
                server_header = headers.get('Server', '')
                
                service_info = {
                    'port': port,
                    'protocol': protocol.lower(),
                    'server': server_header,
                    'status_code': response.status_code
                }
                
                # Extract OS hints from headers
                if 'IIS' in server_header:
                    service_info['os_hint'] = 'Windows'
                elif 'Apache' in server_header:
                    if 'Ubuntu' in server_header:
                        service_info['os_hint'] = 'Ubuntu'
                    elif 'CentOS' in server_header:
                        service_info['os_hint'] = 'CentOS'
                    else:
                        service_info['os_hint'] = 'Linux'
                elif 'nginx' in server_header:
                    service_info['os_hint'] = 'Linux'
                
                result['services'].append(service_info)
                
            except Exception as e:
                continue
        
        return result if result['services'] else None
    
    def _snmp_system_info(self, ip: str) -> Optional[Dict]:
        """SNMP system information gathering"""
        try:
            from pysnmp.hlapi import *
            
            # SNMP OIDs for system information
            oids = {
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysName': '1.3.6.1.2.1.1.5.0',
                'sysContact': '1.3.6.1.2.1.1.4.0'
            }
            
            community = 'public'  # Default community string
            
            for name, oid in oids.items():
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False):
                    
                    if errorIndication:
                        break
                    elif errorStatus:
                        break
                    else:
                        for varBind in varBinds:
                            value = str(varBind[1])
                            
                            if name == 'sysDescr':
                                # Parse system description for OS info
                                os_patterns = {
                                    'Linux': r'Linux.*?(\d+\.\d+\.\d+)',
                                    'Windows': r'Windows.*?(\w+)',
                                    'Cisco': r'Cisco.*?Version (\S+)',
                                    'Juniper': r'Juniper.*?(\d+\.\d+)',
                                    'FreeBSD': r'FreeBSD (\d+\.\d+)'
                                }
                                
                                for os_name, pattern in os_patterns.items():
                                    match = re.search(pattern, value, re.IGNORECASE)
                                    if match:
                                        return {
                                            'os': os_name,
                                            'version': match.group(1) if match.groups() else None,
                                            'description': value
                                        }
        except ImportError:
            print(f"   ⚠️  SNMP library not available")
        except Exception as e:
            print(f"   ⚠️  SNMP scan failed for {ip}: {e}")
        
        return None
    
    def _validate_cmdb_data(self, scan_result: Dict, ci_data: Dict) -> Dict:
        """Validate scan results against CMDB data"""
        
        validation = {
            'os_match': False,
            'version_match': False,
            'discrepancies': []
        }
        
        cmdb_os = ci_data.get('os_name', '').lower()
        cmdb_version = ci_data.get('os_version', '')
        detected_os = scan_result.get('detected_os', '').lower()
        detected_version = scan_result.get('detected_version', '')
        
        # OS name comparison
        if cmdb_os and detected_os:
            if cmdb_os in detected_os or detected_os in cmdb_os:
                validation['os_match'] = True
            else:
                validation['discrepancies'].append(f"OS mismatch: CMDB={cmdb_os}, Detected={detected_os}")
        elif cmdb_os and not detected_os:
            validation['discrepancies'].append("Could not detect OS to validate CMDB data")
        elif not cmdb_os and detected_os:
            validation['discrepancies'].append(f"CMDB missing OS info, detected: {detected_os}")
        
        # Version comparison
        if cmdb_version and detected_version:
            if cmdb_version == detected_version:
                validation['version_match'] = True
            else:
                validation['discrepancies'].append(f"Version mismatch: CMDB={cmdb_version}, Detected={detected_version}")
        
        return validation
    
    def scan_ci_list(self, ci_list: List[Dict]) -> List[Dict]:
        """Scan multiple CIs using threading"""
        
        print(f"🚀 Starting network scan of {len(ci_list)} targets")
        print(f"⚙️  Using {self.max_threads} threads, {self.timeout}s timeout")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit scan jobs
            future_to_ci = {}
            for ci in ci_list:
                ip = ci.get('ip_address')
                if ip:
                    future = executor.submit(self.scan_target, ip, ci)
                    future_to_ci[future] = ci
            
            # Collect results
            completed = 0
            for future in as_completed(future_to_ci):
                ci = future_to_ci[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    error_result = {
                        'ip_address': ci.get('ip_address'),
                        'ci_name': ci.get('name', ''),
                        'reachable': False,
                        'errors': [f"Scan failed: {str(e)}"]
                    }
                    results.append(error_result)
                
                completed += 1
                print(f"   📊 Progress: {completed}/{len(ci_list)} completed")
        
        print(f"✅ Network scan completed: {len(results)} results")
        return results
    
    def export_results(self, results: List[Dict], filename: str = None) -> str:
        """Export scan results to JSON"""
        
        if not filename:
            filename = f"network_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Add summary statistics
        export_data = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_targets': len(results),
                'reachable_targets': len([r for r in results if r.get('reachable')]),
                'os_detected': len([r for r in results if r.get('detected_os')]),
                'scan_methods_used': list(set([method for r in results for method in r.get('scan_methods', [])]))
            },
            'scan_results': results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"📄 Scan results exported to: {filename}")
        return filename

# Demo function
def demo_network_scanning():
    """Demonstrate network scanning capabilities"""
    
    print("🔍 Network OS Detection Demo")
    print("=" * 40)
    
    # Sample CI data for testing
    test_cis = [
        {
            'name': 'google-dns-1',
            'ip_address': '8.8.8.8',
            'os_name': 'Unknown',
            'os_version': ''
        },
        {
            'name': 'google-dns-2', 
            'ip_address': '8.8.4.4',
            'os_name': 'Unknown',
            'os_version': ''
        }
    ]
    
    scanner = NetworkOSScanner(max_threads=2)
    results = scanner.scan_ci_list(test_cis)
    
    # Export results
    scanner.export_results(results)
    
    # Show summary
    print(f"\n📊 Scan Summary:")
    for result in results:
        ip = result['ip_address']
        reachable = "✅" if result['reachable'] else "❌"
        os_info = result.get('detected_os', 'Unknown')
        print(f"   {ip}: {reachable} {os_info}")

if __name__ == "__main__":
    demo_network_scanning()