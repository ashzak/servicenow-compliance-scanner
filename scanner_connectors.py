#!/usr/bin/env python3
"""
Enterprise Scanner Connectors
Agentless device scanning with SSH, WinRM, NAPALM, SNMP, and Nmap fallback
"""

import asyncio
import aiohttp
import logging
import re
import socket
import struct
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import json

# Third-party imports (would be installed via requirements)
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import winrm
except ImportError:
    winrm = None

try:
    from napalm import get_network_driver
except ImportError:
    get_network_driver = None

try:
    from pysnmp.hlapi.asyncore import *
except ImportError:
    pass

from enterprise_architecture import DeviceConnector, ConnectorType, CI, OSFacts

logger = logging.getLogger(__name__)

class SSHConnector(DeviceConnector):
    """SSH-based Linux/Unix scanner"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.connection_cache = {}
    
    async def can_connect(self, ci: CI) -> bool:
        """Check if SSH is available on port 22"""
        if not ci.ip_address:
            return False
        
        # Check for Linux/Unix indicators
        ci_class = ci.ci_class.lower()
        if any(indicator in ci_class for indicator in ["unix", "linux", "computer"]):
            return await self._test_ssh_port(ci.ip_address)
        
        return False
    
    async def _test_ssh_port(self, ip: str) -> bool:
        """Test if SSH port 22 is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts via SSH"""
        
        if not paramiko:
            raise ImportError("paramiko library not available")
        
        username = credentials.get("username")
        password = credentials.get("password")
        private_key = credentials.get("private_key")
        
        if not username or (not password and not private_key):
            raise ValueError("SSH credentials missing")
        
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            connect_kwargs = {
                "hostname": ci.ip_address,
                "username": username,
                "timeout": self.timeout,
                "banner_timeout": 10
            }
            
            if private_key:
                key = paramiko.RSAKey.from_private_key_string(private_key)
                connect_kwargs["pkey"] = key
            else:
                connect_kwargs["password"] = password
            
            ssh.connect(**connect_kwargs)
            
            # Collect OS information
            os_facts = await self._collect_ssh_facts(ssh, ci)
            
            # Close connection
            ssh.close()
            
            return os_facts
            
        except Exception as e:
            logger.error(f"SSH connection failed for {ci.name}: {e}")
            raise
    
    async def _collect_ssh_facts(self, ssh: paramiko.SSHClient, ci: CI) -> OSFacts:
        """Collect OS facts via SSH commands"""
        
        raw_data = {}
        
        # Commands to gather OS information
        commands = {
            "os_release": "cat /etc/os-release 2>/dev/null || cat /etc/*release* 2>/dev/null | head -20",
            "uname": "uname -a",
            "kernel": "uname -r",
            "hostname": "hostname",
            "uptime": "uptime",
            "cpu_info": "cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1",
            "memory": "cat /proc/meminfo 2>/dev/null | grep MemTotal",
            "disk": "df -h /",
            "packages_rpm": "rpm -qa --last 2>/dev/null | head -10",
            "packages_deb": "dpkg -l 2>/dev/null | tail -10",
            "systemctl": "systemctl --version 2>/dev/null | head -1"
        }
        
        # Execute commands
        for cmd_name, cmd in commands.items():
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                if output:
                    raw_data[cmd_name] = output
            except Exception as e:
                logger.debug(f"Command {cmd_name} failed: {e}")
                continue
        
        # Parse OS information
        product, version, edition = self._parse_linux_os(raw_data)
        
        return OSFacts(
            ci_id=ci.id,
            collected_at=datetime.now(),
            product=product,
            version=version,
            edition=edition,
            kernel=raw_data.get("kernel"),
            raw_data=raw_data,
            connector_used=ConnectorType.SSH,
            confidence=0.9 if product else 0.3
        )
    
    def _parse_linux_os(self, raw_data: Dict[str, str]) -> Tuple[str, str, str]:
        """Parse Linux OS information from raw data"""
        
        os_release = raw_data.get("os_release", "")
        uname_output = raw_data.get("uname", "")
        
        # Parse /etc/os-release
        if os_release:
            lines = os_release.split('\n')
            os_info = {}
            
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_info[key.strip()] = value.strip().strip('"')
            
            # Extract product and version
            product = ""
            version = ""
            edition = ""
            
            if "ID" in os_info:
                product = os_info["ID"].lower()
            elif "NAME" in os_info:
                name = os_info["NAME"].lower()
                if "ubuntu" in name:
                    product = "ubuntu"
                elif "red hat" in name or "rhel" in name:
                    product = "rhel"
                elif "centos" in name:
                    product = "centos"
                elif "debian" in name:
                    product = "debian"
                elif "suse" in name or "sles" in name:
                    product = "sles"
            
            if "VERSION_ID" in os_info:
                version = os_info["VERSION_ID"]
            elif "VERSION" in os_info:
                version_str = os_info["VERSION"]
                # Extract version number
                version_match = re.search(r'(\d+\.?\d*)', version_str)
                if version_match:
                    version = version_match.group(1)
            
            if "VARIANT" in os_info:
                edition = os_info["VARIANT"]
            
            return product, version, edition
        
        # Fallback to uname parsing
        if uname_output:
            if "Ubuntu" in uname_output:
                return "ubuntu", "", ""
            elif "Red Hat" in uname_output:
                return "rhel", "", ""
            elif "CentOS" in uname_output:
                return "centos", "", ""
        
        return "", "", ""
    
    def get_connector_type(self) -> ConnectorType:
        return ConnectorType.SSH

class WinRMConnector(DeviceConnector):
    """WinRM-based Windows scanner"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    async def can_connect(self, ci: CI) -> bool:
        """Check if this is a Windows CI and WinRM is available"""
        if not ci.ip_address:
            return False
        
        # Check for Windows indicators
        ci_class = ci.ci_class.lower()
        if "win" in ci_class or "windows" in ci_class:
            return await self._test_winrm_port(ci.ip_address)
        
        return False
    
    async def _test_winrm_port(self, ip: str) -> bool:
        """Test if WinRM ports are open"""
        ports = [5985, 5986]  # HTTP and HTTPS WinRM
        
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                continue
        
        return False
    
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts via WinRM"""
        
        if not winrm:
            raise ImportError("pywinrm library not available")
        
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")
        
        if not username or not password:
            raise ValueError("WinRM credentials missing")
        
        try:
            # Create WinRM session
            if domain:
                username = f"{domain}\\{username}"
            
            # Try HTTPS first, then HTTP
            session = None
            for port, transport in [(5986, "https"), (5985, "http")]:
                try:
                    endpoint = f"{transport}://{ci.ip_address}:{port}/wsman"
                    session = winrm.Session(
                        endpoint,
                        auth=(username, password),
                        transport="ntlm",
                        server_cert_validation="ignore"
                    )
                    
                    # Test connection
                    result = session.run_cmd("echo test")
                    if result.status_code == 0:
                        break
                except:
                    continue
            
            if not session:
                raise ConnectionError("Could not establish WinRM connection")
            
            # Collect OS information
            os_facts = await self._collect_winrm_facts(session, ci)
            
            return os_facts
            
        except Exception as e:
            logger.error(f"WinRM connection failed for {ci.name}: {e}")
            raise
    
    async def _collect_winrm_facts(self, session, ci: CI) -> OSFacts:
        """Collect OS facts via WinRM commands"""
        
        raw_data = {}
        
        # PowerShell commands to gather OS information
        commands = {
            "os_info": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,ServicePackMajorVersion | ConvertTo-Json",
            "computer_info": "Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,TotalPhysicalMemory,NumberOfProcessors | ConvertTo-Json",
            "bios_info": "Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate | ConvertTo-Json",
            "uptime": "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days,Hours,Minutes | ConvertTo-Json",
            "hotfixes": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,Description,InstalledOn | ConvertTo-Json"
        }
        
        # Execute PowerShell commands
        for cmd_name, cmd in commands.items():
            try:
                result = session.run_ps(cmd)
                if result.status_code == 0 and result.std_out:
                    output = result.std_out.decode('utf-8', errors='ignore').strip()
                    try:
                        # Parse JSON output
                        parsed = json.loads(output)
                        raw_data[cmd_name] = parsed
                    except json.JSONDecodeError:
                        raw_data[cmd_name] = output
            except Exception as e:
                logger.debug(f"PowerShell command {cmd_name} failed: {e}")
                continue
        
        # Parse Windows OS information
        product, version, edition = self._parse_windows_os(raw_data)
        
        return OSFacts(
            ci_id=ci.id,
            collected_at=datetime.now(),
            product=product,
            version=version,
            edition=edition,
            raw_data=raw_data,
            connector_used=ConnectorType.WINRM,
            confidence=0.9 if product else 0.3
        )
    
    def _parse_windows_os(self, raw_data: Dict[str, Any]) -> Tuple[str, str, str]:
        """Parse Windows OS information from raw data"""
        
        os_info = raw_data.get("os_info", {})
        
        if isinstance(os_info, dict):
            caption = os_info.get("Caption", "")
            version = os_info.get("Version", "")
            build = os_info.get("BuildNumber", "")
            
            # Determine product
            product = ""
            edition = ""
            
            if "Server" in caption:
                product = "windows-server"
                
                # Extract server version
                if "2022" in caption:
                    version = "2022"
                elif "2019" in caption:
                    version = "2019"
                elif "2016" in caption:
                    version = "2016"
                elif "2012 R2" in caption:
                    version = "2012-r2"
                elif "2012" in caption:
                    version = "2012"
                elif "2008 R2" in caption:
                    version = "2008-r2"
                elif "2008" in caption:
                    version = "2008"
                
                # Extract edition
                if "Datacenter" in caption:
                    edition = "datacenter"
                elif "Standard" in caption:
                    edition = "standard"
                elif "Essentials" in caption:
                    edition = "essentials"
                
            elif "Windows 11" in caption:
                product = "windows"
                version = "11"
            elif "Windows 10" in caption:
                product = "windows"
                version = "10"
            elif "Windows 8.1" in caption:
                product = "windows"
                version = "8.1"
            elif "Windows 8" in caption:
                product = "windows"
                version = "8"
            elif "Windows 7" in caption:
                product = "windows"
                version = "7"
            
            return product, version, edition
        
        return "", "", ""
    
    def get_connector_type(self) -> ConnectorType:
        return ConnectorType.WINRM

class NAPALMConnector(DeviceConnector):
    """NAPALM-based network device scanner"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.supported_drivers = [
            "ios", "iosxr", "nxos", "eos", "junos", 
            "fortios", "panos", "vyos"
        ]
    
    async def can_connect(self, ci: CI) -> bool:
        """Check if this is a network device"""
        if not ci.ip_address:
            return False
        
        # Check for network device indicators
        ci_class = ci.ci_class.lower()
        network_indicators = ["router", "switch", "firewall", "network"]
        
        return any(indicator in ci_class for indicator in network_indicators)
    
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts via NAPALM"""
        
        if not get_network_driver:
            raise ImportError("NAPALM library not available")
        
        username = credentials.get("username")
        password = credentials.get("password")
        driver_name = credentials.get("driver", self._guess_driver(ci))
        
        if not username or not password:
            raise ValueError("Network device credentials missing")
        
        try:
            # Get NAPALM driver
            driver_class = get_network_driver(driver_name)
            
            # Create device connection
            device = driver_class(
                hostname=ci.ip_address,
                username=username,
                password=password,
                timeout=self.timeout
            )
            
            # Connect and collect facts
            device.open()
            
            try:
                facts = device.get_facts()
                interfaces = device.get_interfaces()
                lldp_neighbors = device.get_lldp_neighbors() if hasattr(device, 'get_lldp_neighbors') else {}
                
                raw_data = {
                    "facts": facts,
                    "interfaces": interfaces,
                    "lldp_neighbors": lldp_neighbors
                }
                
                # Parse network OS information
                product, version, edition = self._parse_network_os(facts, driver_name)
                
                return OSFacts(
                    ci_id=ci.id,
                    collected_at=datetime.now(),
                    product=product,
                    version=version,
                    edition=edition,
                    raw_data=raw_data,
                    connector_used=ConnectorType.NAPALM,
                    confidence=0.95
                )
                
            finally:
                device.close()
                
        except Exception as e:
            logger.error(f"NAPALM connection failed for {ci.name}: {e}")
            raise
    
    def _guess_driver(self, ci: CI) -> str:
        """Guess NAPALM driver based on CI information"""
        
        vendor = ci.tags.get("vendor", "").lower()
        model = ci.tags.get("model", "").lower()
        
        # Common vendor mappings
        if "cisco" in vendor or "cisco" in model:
            if "nexus" in model:
                return "nxos"
            elif "asa" in model:
                return "ios"  # Use IOS driver for ASA
            else:
                return "ios"
        elif "juniper" in vendor or "junos" in vendor:
            return "junos"
        elif "arista" in vendor:
            return "eos"
        elif "fortinet" in vendor or "fortigate" in vendor:
            return "fortios"
        elif "palo alto" in vendor or "panos" in vendor:
            return "panos"
        elif "vyos" in vendor:
            return "vyos"
        
        # Default fallback
        return "ios"
    
    def _parse_network_os(self, facts: Dict[str, Any], driver: str) -> Tuple[str, str, str]:
        """Parse network OS information from NAPALM facts"""
        
        os_version = facts.get("os_version", "")
        hostname = facts.get("hostname", "")
        vendor = facts.get("vendor", "")
        model = facts.get("model", "")
        
        # Determine product based on driver and facts
        product = ""
        version = ""
        edition = ""
        
        if driver == "ios":
            product = "cisco-ios"
            # Extract version from os_version string
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "iosxr":
            product = "cisco-iosxr"
            version_match = re.search(r'(\d+\.\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "nxos":
            product = "cisco-nxos"
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "junos":
            product = "junos"
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "eos":
            product = "arista-eos"
            version_match = re.search(r'(\d+\.\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "fortios":
            product = "fortios"
            version_match = re.search(r'v(\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        elif driver == "panos":
            product = "panos"
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                version = version_match.group(1)
        
        return product, version, edition
    
    def get_connector_type(self) -> ConnectorType:
        return ConnectorType.NAPALM

class SNMPConnector(DeviceConnector):
    """SNMP-based fallback scanner for devices without CLI access"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.system_oids = {
            "sysDescr": "1.3.6.1.2.1.1.1.0",
            "sysObjectID": "1.3.6.1.2.1.1.2.0",
            "sysUpTime": "1.3.6.1.2.1.1.3.0",
            "sysContact": "1.3.6.1.2.1.1.4.0",
            "sysName": "1.3.6.1.2.1.1.5.0",
            "sysLocation": "1.3.6.1.2.1.1.6.0"
        }
    
    async def can_connect(self, ci: CI) -> bool:
        """Check if SNMP is available"""
        if not ci.ip_address:
            return False
        
        # SNMP is a fallback for any device
        return True
    
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts via SNMP"""
        
        community = credentials.get("community", "public")
        version = credentials.get("version", "2c")
        
        try:
            raw_data = {}
            
            # Query system OIDs
            for name, oid in self.system_oids.items():
                try:
                    value = await self._snmp_get(ci.ip_address, community, oid)
                    if value:
                        raw_data[name] = value
                except Exception as e:
                    logger.debug(f"SNMP query failed for {oid}: {e}")
                    continue
            
            # Parse SNMP system description
            product, version, edition = self._parse_snmp_sysdescr(
                raw_data.get("sysDescr", "")
            )
            
            return OSFacts(
                ci_id=ci.id,
                collected_at=datetime.now(),
                product=product,
                version=version,
                edition=edition,
                raw_data=raw_data,
                connector_used=ConnectorType.SNMP,
                confidence=0.6 if product else 0.2
            )
            
        except Exception as e:
            logger.error(f"SNMP collection failed for {ci.name}: {e}")
            raise
    
    async def _snmp_get(self, host: str, community: str, oid: str) -> Optional[str]:
        """Perform SNMP GET operation"""
        
        try:
            # Use asyncio subprocess to call snmpget
            cmd = [
                "snmpget", "-v2c", "-c", community, host, oid
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode == 0 and stdout:
                output = stdout.decode('utf-8', errors='ignore').strip()
                # Parse SNMP output format
                if " = " in output:
                    value_part = output.split(" = ", 1)[1]
                    # Remove type prefix (e.g., "STRING: ")
                    if ": " in value_part:
                        return value_part.split(": ", 1)[1].strip('"')
                    return value_part.strip('"')
            
            return None
            
        except Exception as e:
            logger.debug(f"SNMP GET failed for {host} {oid}: {e}")
            return None
    
    def _parse_snmp_sysdescr(self, sysdescr: str) -> Tuple[str, str, str]:
        """Parse system description for OS information"""
        
        if not sysdescr:
            return "", "", ""
        
        sysdescr_lower = sysdescr.lower()
        
        # Network OS patterns
        if "cisco" in sysdescr_lower:
            if "ios" in sysdescr_lower:
                product = "cisco-ios"
                version_match = re.search(r'version (\d+\.\d+)', sysdescr_lower)
                if version_match:
                    return product, version_match.group(1), ""
            elif "nx-os" in sysdescr_lower:
                product = "cisco-nxos"
                version_match = re.search(r'version (\d+\.\d+)', sysdescr_lower)
                if version_match:
                    return product, version_match.group(1), ""
        
        elif "juniper" in sysdescr_lower:
            product = "junos"
            version_match = re.search(r'junos (\d+\.\d+)', sysdescr_lower)
            if version_match:
                return product, version_match.group(1), ""
        
        elif "linux" in sysdescr_lower:
            if "ubuntu" in sysdescr_lower:
                product = "ubuntu"
                version_match = re.search(r'(\d+\.\d+)', sysdescr)
                if version_match:
                    return product, version_match.group(1), ""
            elif "red hat" in sysdescr_lower:
                product = "rhel"
                version_match = re.search(r'(\d+)', sysdescr)
                if version_match:
                    return product, version_match.group(1), ""
        
        elif "windows" in sysdescr_lower:
            if "server" in sysdescr_lower:
                product = "windows-server"
                if "2019" in sysdescr:
                    return product, "2019", ""
                elif "2016" in sysdescr:
                    return product, "2016", ""
                elif "2012" in sysdescr:
                    return product, "2012", ""
        
        return "", "", ""
    
    def get_connector_type(self) -> ConnectorType:
        return ConnectorType.SNMP

class NmapConnector(DeviceConnector):
    """Nmap-based fallback scanner for OS detection"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    async def can_connect(self, ci: CI) -> bool:
        """Nmap can scan any IP address"""
        return bool(ci.ip_address)
    
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts via Nmap OS detection"""
        
        try:
            # Run Nmap OS detection
            cmd = [
                "nmap", "-O", "-sS", "--max-retries", "1", 
                "--host-timeout", "30s", ci.ip_address
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode == 0 and stdout:
                output = stdout.decode('utf-8', errors='ignore')
                
                # Parse Nmap output
                product, version, edition = self._parse_nmap_output(output)
                
                return OSFacts(
                    ci_id=ci.id,
                    collected_at=datetime.now(),
                    product=product,
                    version=version,
                    edition=edition,
                    raw_data={"nmap_output": output},
                    connector_used=ConnectorType.NMAP,
                    confidence=0.4 if product else 0.1
                )
            else:
                raise Exception(f"Nmap failed: {stderr.decode() if stderr else 'Unknown error'}")
                
        except Exception as e:
            logger.error(f"Nmap scan failed for {ci.name}: {e}")
            raise
    
    def _parse_nmap_output(self, output: str) -> Tuple[str, str, str]:
        """Parse Nmap OS detection output"""
        
        # Look for OS details line
        os_lines = []
        for line in output.split('\n'):
            if 'OS details:' in line:
                os_lines.append(line)
        
        if not os_lines:
            return "", "", ""
        
        os_detail = os_lines[0].replace('OS details:', '').strip()
        
        # Parse common OS patterns
        if "Windows" in os_detail:
            if "Server" in os_detail:
                product = "windows-server"
                version_match = re.search(r'(2008|2012|2016|2019|2022)', os_detail)
                if version_match:
                    return product, version_match.group(1), ""
            else:
                product = "windows"
                version_match = re.search(r'Windows (\d+)', os_detail)
                if version_match:
                    return product, version_match.group(1), ""
        
        elif "Linux" in os_detail:
            if "Ubuntu" in os_detail:
                product = "ubuntu"
                version_match = re.search(r'(\d+\.\d+)', os_detail)
                if version_match:
                    return product, version_match.group(1), ""
            elif "Red Hat" in os_detail or "RHEL" in os_detail:
                product = "rhel"
                version_match = re.search(r'(\d+)', os_detail)
                if version_match:
                    return product, version_match.group(1), ""
            elif "CentOS" in os_detail:
                product = "centos"
                version_match = re.search(r'(\d+)', os_detail)
                if version_match:
                    return product, version_match.group(1), ""
        
        elif "Cisco" in os_detail:
            product = "cisco-ios"
            version_match = re.search(r'(\d+\.\d+)', os_detail)
            if version_match:
                return product, version_match.group(1), ""
        
        return "", "", ""
    
    def get_connector_type(self) -> ConnectorType:
        return ConnectorType.NMAP

# Credentials management
class CredentialsManager:
    """Manages device credentials for different connector types"""
    
    def __init__(self, vault_client=None):
        self.vault_client = vault_client
        self.credential_cache = {}
    
    async def get_credentials(self, ci: CI, connector_type: ConnectorType) -> Dict[str, Any]:
        """Get credentials for CI and connector type"""
        
        cache_key = f"{ci.id}_{connector_type.value}"
        
        if cache_key in self.credential_cache:
            return self.credential_cache[cache_key]
        
        if self.vault_client:
            # Get from Vault
            credentials = await self._get_from_vault(ci, connector_type)
        else:
            # Get from environment or default
            credentials = self._get_default_credentials(ci, connector_type)
        
        # Cache for session
        self.credential_cache[cache_key] = credentials
        return credentials
    
    async def _get_from_vault(self, ci: CI, connector_type: ConnectorType) -> Dict[str, Any]:
        """Get credentials from HashiCorp Vault"""
        
        # Implementation would integrate with Vault API
        # This is a placeholder
        path = f"credentials/{ci.business_unit}/{connector_type.value}"
        
        try:
            response = await self.vault_client.read(path)
            return response.get("data", {})
        except Exception as e:
            logger.error(f"Failed to get credentials from Vault: {e}")
            return {}
    
    def _get_default_credentials(self, ci: CI, connector_type: ConnectorType) -> Dict[str, Any]:
        """Get default credentials from environment"""
        
        import os
        
        if connector_type == ConnectorType.SSH:
            return {
                "username": os.getenv("SSH_USERNAME", "admin"),
                "password": os.getenv("SSH_PASSWORD", ""),
                "private_key": os.getenv("SSH_PRIVATE_KEY", "")
            }
        elif connector_type == ConnectorType.WINRM:
            return {
                "username": os.getenv("WINRM_USERNAME", "administrator"),
                "password": os.getenv("WINRM_PASSWORD", ""),
                "domain": os.getenv("WINRM_DOMAIN", "")
            }
        elif connector_type == ConnectorType.NAPALM:
            return {
                "username": os.getenv("NETWORK_USERNAME", "admin"),
                "password": os.getenv("NETWORK_PASSWORD", ""),
                "driver": ci.tags.get("napalm_driver", "ios")
            }
        elif connector_type == ConnectorType.SNMP:
            return {
                "community": os.getenv("SNMP_COMMUNITY", "public"),
                "version": "2c"
            }
        
        return {}

# Example usage
async def demo_scanner_connectors():
    """Demonstrate scanner connectors"""
    
    # Create test CI
    test_ci = CI(
        id="test-001",
        sn_sys_id="test-001",
        name="test-server",
        ci_class="cmdb_ci_unix_server",
        ip_address="192.168.1.100"
    )
    
    # Initialize connectors
    ssh_connector = SSHConnector()
    winrm_connector = WinRMConnector()
    napalm_connector = NAPALMConnector()
    snmp_connector = SNMPConnector()
    nmap_connector = NmapConnector()
    
    connectors = [ssh_connector, winrm_connector, napalm_connector, snmp_connector, nmap_connector]
    
    print(f"Testing connectors for {test_ci.name} ({test_ci.ip_address})")
    
    for connector in connectors:
        can_connect = await connector.can_connect(test_ci)
        print(f"{connector.get_connector_type().value}: {'✓' if can_connect else '✗'}")

if __name__ == "__main__":
    asyncio.run(demo_scanner_connectors())