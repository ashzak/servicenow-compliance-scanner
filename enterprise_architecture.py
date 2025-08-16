#!/usr/bin/env python3
"""
Enterprise CMDB Compliance Tool - Core Architecture
Production-ready, scalable compliance monitoring system
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import hashlib
import uuid

# Core data models
class ComplianceStatus(Enum):
    PASS = "pass"
    WARN = "warn"  
    FAIL = "fail"
    UNKNOWN = "unknown"

class ConnectorType(Enum):
    SSH = "ssh"
    WINRM = "winrm"
    NAPALM = "napalm"
    NETMIKO = "netmiko"
    SNMP = "snmp"
    NMAP = "nmap"

@dataclass
class CI:
    """Configuration Item from ServiceNow CMDB"""
    id: str
    sn_sys_id: str
    name: str
    ci_class: str
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    ip_address: Optional[str] = None
    tags: Dict[str, Any] = None
    last_discovered: Optional[datetime] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class OSFacts:
    """Normalized OS information from device scanning"""
    ci_id: str
    collected_at: datetime
    product: str  # normalized: windows-server, ubuntu, cisco-ios, etc.
    version: str  # normalized: 2019, 20.04, 15.1, etc.
    edition: Optional[str] = None
    kernel: Optional[str] = None
    build: Optional[str] = None
    raw_data: Dict[str, Any] = None
    connector_used: ConnectorType = ConnectorType.SSH
    confidence: float = 1.0  # 0.0-1.0
    
    def __post_init__(self):
        if self.raw_data is None:
            self.raw_data = {}

@dataclass
class LifecycleInfo:
    """Product lifecycle data from endoflife.date and vendors"""
    product: str
    version: str
    eol_date: Optional[datetime] = None
    eos_date: Optional[datetime] = None
    lts: bool = False
    latest_version: Optional[str] = None
    source: str = "endoflife.date"
    fetched_at: datetime = None
    
    def __post_init__(self):
        if self.fetched_at is None:
            self.fetched_at = datetime.now()
    
    @property
    def is_eol(self) -> bool:
        if not self.eol_date:
            return False
        return datetime.now() > self.eol_date
    
    @property
    def is_eos(self) -> bool:
        if not self.eos_date:
            return False
        return datetime.now() > self.eos_date
    
    @property
    def days_to_eol(self) -> Optional[int]:
        if not self.eol_date:
            return None
        delta = self.eol_date - datetime.now()
        return delta.days

@dataclass
class ComplianceFinding:
    """Compliance assessment result"""
    ci_id: str
    evaluated_at: datetime
    status: ComplianceStatus
    reason: str
    evidence: Dict[str, Any]
    policy_id: str
    risk_score: int = 0  # 0-100
    remediation: Optional[str] = None
    waiver_until: Optional[datetime] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}

# Abstract base classes for pluggable components

class DeviceConnector(ABC):
    """Abstract base for device scanning connectors"""
    
    @abstractmethod
    async def can_connect(self, ci: CI) -> bool:
        """Check if this connector can handle the CI"""
        pass
    
    @abstractmethod
    async def collect_facts(self, ci: CI, credentials: Dict[str, Any]) -> OSFacts:
        """Collect OS facts from the device"""
        pass
    
    @abstractmethod
    def get_connector_type(self) -> ConnectorType:
        """Return the connector type"""
        pass

class LifecycleProvider(ABC):
    """Abstract base for lifecycle data providers"""
    
    @abstractmethod
    async def get_lifecycle_info(self, product: str, version: str) -> Optional[LifecycleInfo]:
        """Get lifecycle information for a product/version"""
        pass
    
    @abstractmethod
    async def refresh_cache(self) -> None:
        """Refresh cached lifecycle data"""
        pass

class PolicyEngine(ABC):
    """Abstract base for compliance policy engines"""
    
    @abstractmethod
    async def evaluate(
        self, 
        ci: CI, 
        os_facts: OSFacts, 
        lifecycle: LifecycleInfo,
        policies: List[Dict[str, Any]]
    ) -> ComplianceFinding:
        """Evaluate compliance for a CI"""
        pass

# Core service interfaces

class CMDBService(ABC):
    """ServiceNow CMDB integration service"""
    
    @abstractmethod
    async def get_cis(
        self, 
        ci_classes: List[str] = None,
        filters: Dict[str, Any] = None,
        limit: int = None
    ) -> List[CI]:
        """Retrieve CIs from ServiceNow CMDB"""
        pass
    
    @abstractmethod
    async def update_ci_compliance(
        self, 
        ci_id: str, 
        finding: ComplianceFinding
    ) -> bool:
        """Update CI with compliance information"""
        pass
    
    @abstractmethod
    async def create_compliance_record(
        self, 
        finding: ComplianceFinding
    ) -> str:
        """Create compliance record in ServiceNow"""
        pass

class ScannerService:
    """Orchestrates device scanning across multiple connectors"""
    
    def __init__(self):
        self.connectors: List[DeviceConnector] = []
        self.credentials_manager = None
        self.circuit_breaker = CircuitBreaker()
    
    def register_connector(self, connector: DeviceConnector) -> None:
        """Register a device connector"""
        self.connectors.append(connector)
    
    async def scan_ci(self, ci: CI) -> Optional[OSFacts]:
        """Scan a single CI using appropriate connector"""
        
        # Circuit breaker check
        if not await self.circuit_breaker.can_proceed(ci.ip_address):
            logging.warning(f"Circuit breaker open for {ci.ip_address}")
            return None
        
        # Find appropriate connector
        for connector in self.connectors:
            try:
                if await connector.can_connect(ci):
                    credentials = await self.credentials_manager.get_credentials(
                        ci, connector.get_connector_type()
                    )
                    
                    facts = await asyncio.wait_for(
                        connector.collect_facts(ci, credentials),
                        timeout=30.0  # 30 second timeout
                    )
                    
                    await self.circuit_breaker.record_success(ci.ip_address)
                    return facts
                    
            except asyncio.TimeoutError:
                logging.warning(f"Timeout scanning {ci.name} with {connector.get_connector_type()}")
                await self.circuit_breaker.record_failure(ci.ip_address)
            except Exception as e:
                logging.error(f"Error scanning {ci.name} with {connector.get_connector_type()}: {e}")
                await self.circuit_breaker.record_failure(ci.ip_address)
        
        return None

class ComplianceEngine:
    """Main compliance assessment engine"""
    
    def __init__(
        self,
        cmdb_service: CMDBService,
        scanner_service: ScannerService,
        lifecycle_provider: LifecycleProvider,
        policy_engine: PolicyEngine
    ):
        self.cmdb = cmdb_service
        self.scanner = scanner_service
        self.lifecycle = lifecycle_provider
        self.policy = policy_engine
        self.normalizer = ProductNormalizer()
    
    async def assess_compliance(
        self, 
        ci_filters: Dict[str, Any] = None,
        batch_size: int = 50
    ) -> List[ComplianceFinding]:
        """Run full compliance assessment"""
        
        findings = []
        
        # Get CIs from CMDB
        cis = await self.cmdb.get_cis(filters=ci_filters)
        logging.info(f"Assessing {len(cis)} CIs for compliance")
        
        # Process in batches
        for i in range(0, len(cis), batch_size):
            batch = cis[i:i + batch_size]
            batch_tasks = [self._assess_single_ci(ci) for ci in batch]
            
            batch_results = await asyncio.gather(
                *batch_tasks, 
                return_exceptions=True
            )
            
            for result in batch_results:
                if isinstance(result, ComplianceFinding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    logging.error(f"Error in batch assessment: {result}")
        
        return findings
    
    async def _assess_single_ci(self, ci: CI) -> Optional[ComplianceFinding]:
        """Assess compliance for a single CI"""
        
        try:
            # Scan device for actual OS facts
            os_facts = await self.scanner.scan_ci(ci)
            if not os_facts:
                return ComplianceFinding(
                    ci_id=ci.id,
                    evaluated_at=datetime.now(),
                    status=ComplianceStatus.UNKNOWN,
                    reason="Unable to collect OS facts",
                    evidence={"error": "Device unreachable or unsupported"},
                    policy_id="baseline"
                )
            
            # Normalize product information
            normalized = await self.normalizer.normalize(os_facts)
            
            # Get lifecycle information
            lifecycle = await self.lifecycle.get_lifecycle_info(
                normalized.product, 
                normalized.version
            )
            
            if not lifecycle:
                return ComplianceFinding(
                    ci_id=ci.id,
                    evaluated_at=datetime.now(),
                    status=ComplianceStatus.UNKNOWN,
                    reason="No lifecycle data available",
                    evidence={"product": normalized.product, "version": normalized.version},
                    policy_id="baseline"
                )
            
            # Evaluate against policies
            policies = await self._get_applicable_policies(ci, normalized)
            finding = await self.policy.evaluate(ci, normalized, lifecycle, policies)
            
            # Update CMDB with findings
            await self.cmdb.update_ci_compliance(ci.id, finding)
            
            return finding
            
        except Exception as e:
            logging.error(f"Error assessing CI {ci.name}: {e}")
            return ComplianceFinding(
                ci_id=ci.id,
                evaluated_at=datetime.now(),
                status=ComplianceStatus.UNKNOWN,
                reason=f"Assessment error: {str(e)}",
                evidence={"error": str(e)},
                policy_id="baseline"
            )
    
    async def _get_applicable_policies(
        self, 
        ci: CI, 
        os_facts: OSFacts
    ) -> List[Dict[str, Any]]:
        """Get policies applicable to this CI"""
        
        # Default baseline policy
        baseline_policy = {
            "id": "baseline",
            "name": "Baseline EOL/EOS Policy",
            "rules": {
                "eol_fail": True,
                "eos_fail": True,
                "warn_days": 180,
                "min_versions": {}
            }
        }
        
        # Add product-specific policies
        policies = [baseline_policy]
        
        # Add BU-specific policies if applicable
        if ci.business_unit:
            bu_policy = await self._get_bu_policy(ci.business_unit)
            if bu_policy:
                policies.append(bu_policy)
        
        return policies
    
    async def _get_bu_policy(self, business_unit: str) -> Optional[Dict[str, Any]]:
        """Get business unit specific policy"""
        # This would typically come from a policy database
        return None

class ProductNormalizer:
    """Normalizes raw OS strings to standard product/version"""
    
    def __init__(self):
        self.normalization_rules = {
            # Windows patterns
            r"Microsoft Windows Server (\d{4}).*": ("windows-server", r"\1"),
            r"Windows (\d+)": ("windows", r"\1"),
            
            # Linux patterns  
            r"Ubuntu (\d+\.\d+)": ("ubuntu", r"\1"),
            r"Red Hat Enterprise Linux.*?(\d+)": ("rhel", r"\1"),
            r"CentOS.*?(\d+)": ("centos", r"\1"),
            
            # Network OS patterns
            r"Cisco IOS.*?Version (\d+\.\d+)": ("cisco-ios", r"\1"),
            r"Juniper.*?JUNOS (\d+\.\d+)": ("junos", r"\1"),
        }
    
    async def normalize(self, os_facts: OSFacts) -> OSFacts:
        """Normalize OS facts to standard format"""
        
        if os_facts.product and os_facts.version:
            # Already normalized
            return os_facts
        
        # Extract raw OS string
        raw_os = os_facts.raw_data.get("os_string", "")
        
        # Apply normalization rules
        import re
        for pattern, (product, version_group) in self.normalization_rules.items():
            match = re.search(pattern, raw_os, re.IGNORECASE)
            if match:
                os_facts.product = product
                os_facts.version = match.expand(version_group)
                os_facts.confidence = 0.9
                break
        
        return os_facts

class CircuitBreaker:
    """Circuit breaker for device connections"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures: Dict[str, int] = {}
        self.last_failure: Dict[str, datetime] = {}
    
    async def can_proceed(self, host: str) -> bool:
        """Check if operations can proceed for host"""
        
        if host not in self.failures:
            return True
        
        # Check if circuit breaker should reset
        if (host in self.last_failure and 
            datetime.now() - self.last_failure[host] > timedelta(seconds=self.timeout)):
            self.failures[host] = 0
            return True
        
        return self.failures[host] < self.failure_threshold
    
    async def record_success(self, host: str) -> None:
        """Record successful operation"""
        if host in self.failures:
            self.failures[host] = 0
    
    async def record_failure(self, host: str) -> None:
        """Record failed operation"""
        self.failures[host] = self.failures.get(host, 0) + 1
        self.last_failure[host] = datetime.now()

# Example usage and factory
class ComplianceToolFactory:
    """Factory for creating compliance tool instances"""
    
    @staticmethod
    def create_enterprise_tool(config: Dict[str, Any]) -> ComplianceEngine:
        """Create a fully configured enterprise compliance tool"""
        
        # Initialize services based on config
        cmdb_service = ServiceNowCMDBService(config.get("servicenow", {}))
        
        scanner_service = ScannerService()
        # Register connectors based on config
        if config.get("connectors", {}).get("ssh", True):
            scanner_service.register_connector(SSHConnector())
        if config.get("connectors", {}).get("winrm", True):
            scanner_service.register_connector(WinRMConnector())
        if config.get("connectors", {}).get("napalm", True):
            scanner_service.register_connector(NAPALMConnector())
        
        lifecycle_provider = EndOfLifeDateProvider(config.get("eol_api", {}))
        policy_engine = OPAPolicyEngine(config.get("opa", {}))
        
        return ComplianceEngine(
            cmdb_service=cmdb_service,
            scanner_service=scanner_service,
            lifecycle_provider=lifecycle_provider,
            policy_engine=policy_engine
        )

# Configuration schema
DEFAULT_CONFIG = {
    "servicenow": {
        "instance": "",
        "username": "",
        "password": "",
        "table_api_version": "v1"
    },
    "connectors": {
        "ssh": True,
        "winrm": True,
        "napalm": True,
        "snmp": True,
        "nmap_fallback": True
    },
    "eol_api": {
        "base_url": "https://endoflife.date/api",
        "cache_ttl": 86400  # 24 hours
    },
    "opa": {
        "policy_dir": "./policies",
        "decision_log": True
    },
    "scanning": {
        "batch_size": 50,
        "timeout": 30,
        "max_concurrent": 100,
        "circuit_breaker": {
            "failure_threshold": 5,
            "timeout": 300
        }
    },
    "database": {
        "url": "postgresql://user:pass@localhost/compliance",
        "pool_size": 20
    },
    "vault": {
        "url": "http://localhost:8200",
        "auth_method": "userpass"
    },
    "observability": {
        "jaeger_endpoint": "http://localhost:14268/api/traces",
        "metrics_port": 8090
    }
}

if __name__ == "__main__":
    # Example usage
    config = DEFAULT_CONFIG
    tool = ComplianceToolFactory.create_enterprise_tool(config)
    
    # Run assessment
    async def main():
        findings = await tool.assess_compliance()
        print(f"Assessment complete: {len(findings)} findings")
        
        for finding in findings[:5]:  # Show first 5
            print(f"CI: {finding.ci_id}, Status: {finding.status.value}, Reason: {finding.reason}")
    
    # asyncio.run(main())