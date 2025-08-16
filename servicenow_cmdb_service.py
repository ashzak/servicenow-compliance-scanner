#!/usr/bin/env python3
"""
Enterprise ServiceNow CMDB Service
Production-grade ServiceNow Table API integration with pagination, caching, and error handling
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode
import base64

from enterprise_architecture import CMDBService, CI, ComplianceFinding

logger = logging.getLogger(__name__)

class ServiceNowCMDBService(CMDBService):
    """Production ServiceNow CMDB integration service"""
    
    def __init__(self, config: Dict[str, Any]):
        self.instance = config.get("instance")
        self.username = config.get("username")
        self.password = config.get("password")
        self.api_version = config.get("table_api_version", "v1")
        self.base_url = f"https://{self.instance}/api/now/table"
        self.timeout = aiohttp.ClientTimeout(total=30)
        
        # Rate limiting
        self.rate_limiter = AsyncRateLimiter(calls=100, period=60)  # 100 calls per minute
        
        # Caching
        self.cache_ttl = config.get("cache_ttl", 300)  # 5 minutes
        self.cache: Dict[str, Any] = {}
        
        # Authentication
        self.auth_header = self._create_auth_header()
        
        # CI class mappings
        self.ci_class_fields = {
            "cmdb_ci_computer": [
                "sys_id", "name", "ip_address", "fqdn", "sys_class_name",
                "operational_status", "os", "os_version", "os_service_pack",
                "assigned_to", "managed_by", "business_service", "location",
                "environment", "install_status", "discovery_source",
                "last_discovered", "sys_created_on", "sys_updated_on"
            ],
            "cmdb_ci_win_server": [
                "sys_id", "name", "ip_address", "fqdn", "sys_class_name",
                "operational_status", "os", "os_version", "os_service_pack",
                "ram", "cpu_count", "disk_space", "assigned_to", "managed_by",
                "business_service", "location", "environment", "install_status"
            ],
            "cmdb_ci_unix_server": [
                "sys_id", "name", "ip_address", "fqdn", "sys_class_name",
                "operational_status", "os", "os_version", "kernel_release",
                "ram", "cpu_count", "disk_space", "assigned_to", "managed_by"
            ],
            "cmdb_ci_network": [
                "sys_id", "name", "ip_address", "sys_class_name",
                "operational_status", "os", "os_version", "firmware_version",
                "vendor", "model_number", "serial_number", "location"
            ],
            "cmdb_ci_router": [
                "sys_id", "name", "ip_address", "sys_class_name",
                "operational_status", "os", "os_version", "firmware_version",
                "vendor", "model_number", "ports", "location"
            ],
            "cmdb_ci_switch": [
                "sys_id", "name", "ip_address", "sys_class_name",
                "operational_status", "os", "os_version", "firmware_version",
                "vendor", "model_number", "ports", "location"
            ],
            "cmdb_ci_firewall": [
                "sys_id", "name", "ip_address", "sys_class_name",
                "operational_status", "os", "os_version", "firmware_version",
                "vendor", "model_number", "location"
            ]
        }
    
    def _create_auth_header(self) -> str:
        """Create basic auth header"""
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded_credentials}"
    
    async def get_cis(
        self,
        ci_classes: List[str] = None,
        filters: Dict[str, Any] = None,
        limit: int = None
    ) -> List[CI]:
        """Retrieve CIs from ServiceNow CMDB with pagination and filtering"""
        
        if ci_classes is None:
            ci_classes = [
                "cmdb_ci_computer",
                "cmdb_ci_win_server", 
                "cmdb_ci_unix_server",
                "cmdb_ci_router",
                "cmdb_ci_switch",
                "cmdb_ci_firewall"
            ]
        
        all_cis = []
        
        # Process each CI class
        for ci_class in ci_classes:
            logger.info(f"Fetching CIs for class: {ci_class}")
            
            try:
                cis = await self._fetch_ci_class(ci_class, filters, limit)
                all_cis.extend(cis)
                logger.info(f"Retrieved {len(cis)} CIs from {ci_class}")
                
            except Exception as e:
                logger.error(f"Error fetching {ci_class}: {e}")
                continue
        
        logger.info(f"Total CIs retrieved: {len(all_cis)}")
        return all_cis
    
    async def _fetch_ci_class(
        self,
        ci_class: str,
        filters: Dict[str, Any] = None,
        limit: int = None
    ) -> List[CI]:
        """Fetch CIs for a specific class with pagination"""
        
        cis = []
        offset = 0
        page_size = 1000  # ServiceNow recommended page size
        
        # Build query parameters
        query_params = {
            "sysparm_query": self._build_query(ci_class, filters),
            "sysparm_fields": ",".join(self.ci_class_fields.get(ci_class, [])),
            "sysparm_limit": page_size,
            "sysparm_offset": offset
        }
        
        while True:
            # Rate limiting
            await self.rate_limiter.acquire()
            
            # Update offset for pagination
            query_params["sysparm_offset"] = offset
            
            try:
                async with aiohttp.ClientSession(timeout=self.timeout) as session:
                    url = f"{self.base_url}/{ci_class}"
                    headers = {
                        "Authorization": self.auth_header,
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    }
                    
                    async with session.get(url, params=query_params, headers=headers) as response:
                        if response.status != 200:
                            logger.error(f"ServiceNow API error: {response.status} - {await response.text()}")
                            break
                        
                        data = await response.json()
                        records = data.get("result", [])
                        
                        if not records:
                            break  # No more records
                        
                        # Convert to CI objects
                        for record in records:
                            ci = self._record_to_ci(record, ci_class)
                            if ci:
                                cis.append(ci)
                        
                        # Check if we've hit our limit
                        if limit and len(cis) >= limit:
                            cis = cis[:limit]
                            break
                        
                        # Check if we've reached the end
                        if len(records) < page_size:
                            break
                        
                        offset += page_size
                        
            except asyncio.TimeoutError:
                logger.error(f"Timeout fetching {ci_class} at offset {offset}")
                break
            except Exception as e:
                logger.error(f"Error fetching {ci_class} at offset {offset}: {e}")
                break
        
        return cis
    
    def _build_query(self, ci_class: str, filters: Dict[str, Any] = None) -> str:
        """Build ServiceNow query string"""
        
        query_parts = []
        
        # Base filters for operational CIs
        query_parts.append("operational_status=1")  # Operational
        query_parts.append("ip_addressISNOTEMPTY")   # Has IP address
        
        # Add custom filters
        if filters:
            for field, value in filters.items():
                if isinstance(value, list):
                    # IN query
                    value_str = ",".join(str(v) for v in value)
                    query_parts.append(f"{field}IN{value_str}")
                else:
                    query_parts.append(f"{field}={value}")
        
        return "^".join(query_parts)
    
    def _record_to_ci(self, record: Dict[str, Any], ci_class: str) -> Optional[CI]:
        """Convert ServiceNow record to CI object"""
        
        try:
            # Parse last discovered date
            last_discovered = None
            if record.get("last_discovered"):
                try:
                    last_discovered = datetime.strptime(
                        record["last_discovered"], 
                        "%Y-%m-%d %H:%M:%S"
                    )
                except:
                    pass
            
            return CI(
                id=record["sys_id"],
                sn_sys_id=record["sys_id"],
                name=record.get("name", ""),
                ci_class=ci_class,
                owner=record.get("assigned_to"),
                business_unit=record.get("business_service"),
                ip_address=record.get("ip_address"),
                last_discovered=last_discovered,
                tags={
                    "fqdn": record.get("fqdn"),
                    "location": record.get("location"),
                    "environment": record.get("environment"),
                    "install_status": record.get("install_status"),
                    "discovery_source": record.get("discovery_source"),
                    "cmdb_os": record.get("os"),
                    "cmdb_os_version": record.get("os_version"),
                    "vendor": record.get("vendor"),
                    "model": record.get("model_number"),
                    "serial": record.get("serial_number")
                }
            )
            
        except Exception as e:
            logger.error(f"Error converting record to CI: {e}")
            return None
    
    async def update_ci_compliance(
        self, 
        ci_id: str, 
        finding: ComplianceFinding
    ) -> bool:
        """Update CI with compliance information"""
        
        try:
            # Rate limiting
            await self.rate_limiter.acquire()
            
            # Prepare update data
            update_data = {
                "u_compliance_status": finding.status.value,
                "u_compliance_reason": finding.reason,
                "u_risk_score": finding.risk_score,
                "u_last_compliance_check": finding.evaluated_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Add EOL information if available
            if "eol_date" in finding.evidence:
                update_data["u_eol_date"] = finding.evidence["eol_date"]
            if "days_to_eol" in finding.evidence:
                update_data["u_days_to_eol"] = finding.evidence["days_to_eol"]
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.base_url}/cmdb_ci/{ci_id}"
                headers = {
                    "Authorization": self.auth_header,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
                
                async with session.patch(url, json=update_data, headers=headers) as response:
                    if response.status in [200, 201]:
                        logger.debug(f"Updated CI {ci_id} with compliance status")
                        return True
                    else:
                        logger.error(f"Failed to update CI {ci_id}: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Error updating CI {ci_id}: {e}")
            return False
    
    async def create_compliance_record(
        self, 
        finding: ComplianceFinding
    ) -> str:
        """Create compliance record in custom ServiceNow table"""
        
        try:
            # Rate limiting
            await self.rate_limiter.acquire()
            
            # Prepare compliance record
            record_data = {
                "u_ci": finding.ci_id,
                "u_status": finding.status.value,
                "u_reason": finding.reason,
                "u_risk_score": finding.risk_score,
                "u_evaluated_at": finding.evaluated_at.strftime("%Y-%m-%d %H:%M:%S"),
                "u_policy_id": finding.policy_id,
                "u_evidence": json.dumps(finding.evidence),
                "u_remediation": finding.remediation or ""
            }
            
            if finding.waiver_until:
                record_data["u_waiver_until"] = finding.waiver_until.strftime("%Y-%m-%d %H:%M:%S")
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.base_url}/u_cmdb_compliance"  # Custom table
                headers = {
                    "Authorization": self.auth_header,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
                
                async with session.post(url, json=record_data, headers=headers) as response:
                    if response.status in [200, 201]:
                        result = await response.json()
                        record_id = result.get("result", {}).get("sys_id")
                        logger.debug(f"Created compliance record {record_id}")
                        return record_id
                    else:
                        logger.error(f"Failed to create compliance record: {response.status}")
                        return ""
                        
        except Exception as e:
            logger.error(f"Error creating compliance record: {e}")
            return ""
    
    async def get_business_units(self) -> List[Dict[str, str]]:
        """Get list of business units from ServiceNow"""
        
        try:
            await self.rate_limiter.acquire()
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.base_url}/core_company"
                headers = {
                    "Authorization": self.auth_header,
                    "Accept": "application/json"
                }
                
                params = {
                    "sysparm_fields": "sys_id,name",
                    "sysparm_limit": 1000
                }
                
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return [
                            {"id": record["sys_id"], "name": record["name"]}
                            for record in data.get("result", [])
                        ]
                    else:
                        logger.error(f"Failed to get business units: {response.status}")
                        return []
                        
        except Exception as e:
            logger.error(f"Error getting business units: {e}")
            return []
    
    async def create_change_request(
        self, 
        findings: List[ComplianceFinding],
        change_template: Dict[str, Any] = None
    ) -> str:
        """Create change request for compliance remediation"""
        
        try:
            await self.rate_limiter.acquire()
            
            # Prepare change request
            affected_cis = [f.ci_id for f in findings]
            critical_count = len([f for f in findings if f.status.value == "fail"])
            
            change_data = {
                "short_description": f"OS Compliance Remediation - {critical_count} Critical Issues",
                "description": self._generate_change_description(findings),
                "type": "standard",
                "risk": "moderate" if critical_count > 0 else "low",
                "category": "Software",
                "subcategory": "Operating System",
                "u_affected_cis": ",".join(affected_cis[:10]),  # Limit for field size
                "state": "new"
            }
            
            # Apply template overrides
            if change_template:
                change_data.update(change_template)
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.base_url}/change_request"
                headers = {
                    "Authorization": self.auth_header,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
                
                async with session.post(url, json=change_data, headers=headers) as response:
                    if response.status in [200, 201]:
                        result = await response.json()
                        change_number = result.get("result", {}).get("number")
                        logger.info(f"Created change request {change_number}")
                        return change_number
                    else:
                        logger.error(f"Failed to create change request: {response.status}")
                        return ""
                        
        except Exception as e:
            logger.error(f"Error creating change request: {e}")
            return ""
    
    def _generate_change_description(self, findings: List[ComplianceFinding]) -> str:
        """Generate change request description from findings"""
        
        critical_findings = [f for f in findings if f.status.value == "fail"]
        warning_findings = [f for f in findings if f.status.value == "warn"]
        
        description = "Automated OS Compliance Remediation\n\n"
        
        if critical_findings:
            description += f"CRITICAL ISSUES ({len(critical_findings)}):\n"
            for finding in critical_findings[:5]:  # Limit to first 5
                description += f"- CI {finding.ci_id}: {finding.reason}\n"
            if len(critical_findings) > 5:
                description += f"... and {len(critical_findings) - 5} more\n"
            description += "\n"
        
        if warning_findings:
            description += f"WARNING ISSUES ({len(warning_findings)}):\n"
            for finding in warning_findings[:3]:  # Limit to first 3
                description += f"- CI {finding.ci_id}: {finding.reason}\n"
            if len(warning_findings) > 3:
                description += f"... and {len(warning_findings) - 3} more\n"
        
        description += "\nRemediation actions required to maintain compliance."
        
        return description

class AsyncRateLimiter:
    """Async rate limiter for API calls"""
    
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
        self.call_times = []
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire rate limit token"""
        async with self.lock:
            now = datetime.now()
            
            # Remove old calls outside the period
            cutoff = now - timedelta(seconds=self.period)
            self.call_times = [t for t in self.call_times if t > cutoff]
            
            # Check if we can make a call
            if len(self.call_times) >= self.calls:
                # Calculate sleep time
                oldest_call = min(self.call_times)
                sleep_time = (oldest_call + timedelta(seconds=self.period) - now).total_seconds()
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    return await self.acquire()  # Retry
            
            # Record this call
            self.call_times.append(now)

# Example usage
async def demo_servicenow_integration():
    """Demonstrate ServiceNow CMDB integration"""
    
    config = {
        "instance": "dev12345.service-now.com",
        "username": "admin",
        "password": "password",
        "cache_ttl": 300
    }
    
    service = ServiceNowCMDBService(config)
    
    # Get CIs
    cis = await service.get_cis(
        ci_classes=["cmdb_ci_win_server", "cmdb_ci_unix_server"],
        limit=10
    )
    
    print(f"Retrieved {len(cis)} CIs from ServiceNow")
    
    for ci in cis:
        print(f"- {ci.name} ({ci.ci_class}) - {ci.ip_address}")

if __name__ == "__main__":
    # Run demo
    asyncio.run(demo_servicenow_integration())