#!/usr/bin/env python3
"""
GraphQL Schema for Enterprise CMDB Compliance API
Provides flexible, efficient data querying with Strawberry GraphQL
"""

import strawberry
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
import asyncio
import logging

logger = logging.getLogger(__name__)

# GraphQL Enums
@strawberry.enum
class ComplianceStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

@strawberry.enum
class ConnectorType(Enum):
    SSH = "ssh"
    WINRM = "winrm"
    NAPALM = "napalm"
    SNMP = "snmp"
    NMAP = "nmap"

@strawberry.enum
class CIClass(Enum):
    SERVER = "cmdb_ci_server"
    NETWORK = "cmdb_ci_netgear"
    DATABASE = "cmdb_ci_database"
    APPLICATION = "cmdb_ci_application"
    STORAGE = "cmdb_ci_storage"

# GraphQL Types
@strawberry.type
class CI:
    id: str
    name: str
    ci_class: str
    business_unit: Optional[str]
    owner: Optional[str]
    ip_address: Optional[str]
    location: Optional[str]
    environment: Optional[str]
    criticality: Optional[str]
    tags: Optional[str]

@strawberry.type
class OSFacts:
    ci_id: str
    collected_at: datetime
    product: Optional[str]
    version: Optional[str]
    edition: Optional[str]
    kernel: Optional[str]
    confidence: float
    connector_used: ConnectorType

@strawberry.type
class LifecycleInfo:
    product: str
    version: str
    eol_date: Optional[datetime]
    eos_date: Optional[datetime]
    is_eol: bool
    is_eos: bool
    days_to_eol: Optional[int]
    days_to_eos: Optional[int]
    lts: bool
    latest_version: Optional[str]
    source: str

@strawberry.type
class ComplianceFinding:
    id: str
    ci_id: str
    evaluated_at: datetime
    status: ComplianceStatus
    reason: str
    risk_score: int
    policy_id: str
    remediation: Optional[str]
    evidence: Optional[str]
    
    # Relationships
    @strawberry.field
    async def ci(self) -> Optional[CI]:
        """Get the CI associated with this finding"""
        from database_layer import DatabaseManager
        try:
            db_manager = get_db_manager()
            if db_manager:
                ci_data = await db_manager.get_ci_by_id(self.ci_id)
                if ci_data:
                    return CI(
                        id=ci_data['id'],
                        name=ci_data['name'],
                        ci_class=ci_data['ci_class'],
                        business_unit=ci_data.get('business_unit'),
                        owner=ci_data.get('owner'),
                        ip_address=ci_data.get('ip_address'),
                        location=ci_data.get('location'),
                        environment=ci_data.get('environment'),
                        criticality=ci_data.get('criticality'),
                        tags=str(ci_data.get('tags', {}))
                    )
        except Exception as e:
            logger.error(f"Error fetching CI for finding {self.id}: {e}")
        return None
    
    @strawberry.field
    async def os_facts(self) -> Optional[OSFacts]:
        """Get OS facts for this CI"""
        from database_layer import DatabaseManager
        try:
            db_manager = get_db_manager()
            if db_manager:
                os_data = await db_manager.get_latest_os_facts(self.ci_id)
                if os_data:
                    return OSFacts(
                        ci_id=os_data['ci_id'],
                        collected_at=os_data['collected_at'],
                        product=os_data.get('product'),
                        version=os_data.get('version'),
                        edition=os_data.get('edition'),
                        kernel=os_data.get('kernel'),
                        confidence=os_data.get('confidence', 0.0),
                        connector_used=ConnectorType(os_data.get('connector_used', 'unknown'))
                    )
        except Exception as e:
            logger.error(f"Error fetching OS facts for CI {self.ci_id}: {e}")
        return None

@strawberry.type
class BusinessUnit:
    name: str
    system_count: int
    critical_count: int
    compliant_count: int
    warning_count: int
    compliance_score: float
    avg_risk_score: float
    
    @strawberry.field
    async def systems(self) -> List[CI]:
        """Get all systems in this business unit"""
        from database_layer import DatabaseManager
        try:
            db_manager = get_db_manager()
            if db_manager:
                systems = await db_manager.get_cis_by_business_unit(self.name)
                return [
                    CI(
                        id=system['id'],
                        name=system['name'],
                        ci_class=system['ci_class'],
                        business_unit=system.get('business_unit'),
                        owner=system.get('owner'),
                        ip_address=system.get('ip_address'),
                        location=system.get('location'),
                        environment=system.get('environment'),
                        criticality=system.get('criticality'),
                        tags=str(system.get('tags', {}))
                    ) for system in systems
                ]
        except Exception as e:
            logger.error(f"Error fetching systems for business unit {self.name}: {e}")
        return []

@strawberry.type
class ComplianceSummary:
    total_systems: int
    compliant_systems: int
    warning_systems: int
    critical_systems: int
    compliance_score: float
    avg_risk_score: float
    last_updated: datetime

@strawberry.type
class ScanStatus:
    scan_id: str
    status: str
    progress: int
    total_systems: int
    completed_systems: int
    started_at: datetime
    estimated_completion: Optional[datetime]

# Input Types
@strawberry.input
class ComplianceFilter:
    status: Optional[ComplianceStatus] = None
    business_unit: Optional[str] = None
    ci_class: Optional[str] = None
    min_risk_score: Optional[int] = None
    max_risk_score: Optional[int] = None
    days_since_scan: Optional[int] = None

@strawberry.input
class DateRange:
    start_date: datetime
    end_date: datetime

# Global database manager instance
_db_manager = None

def get_db_manager():
    """Get or create database manager instance"""
    global _db_manager
    if _db_manager is None:
        try:
            from database_layer import DatabaseManager, DatabaseConfig
            import json
            from pathlib import Path
            
            config_file = Path(__file__).parent / "database_config.json"
            if config_file.exists():
                with open(config_file) as f:
                    config_data = json.load(f)
                
                db_config = DatabaseConfig(
                    host=config_data["database"]["host"],
                    port=config_data["database"]["port"],
                    database=config_data["database"]["database"],
                    username=config_data["database"]["username"],
                    password=config_data["database"]["password"]
                )
                
                _db_manager = DatabaseManager(db_config)
                # Note: initialize() should be called separately in startup
        except Exception as e:
            logger.error(f"Failed to create database manager: {e}")
    
    return _db_manager

# Queries
@strawberry.type
class Query:
    
    @strawberry.field
    async def compliance_findings(
        self, 
        filter: Optional[ComplianceFilter] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[ComplianceFinding]:
        """Get compliance findings with optional filtering"""
        
        try:
            db_manager = get_db_manager()
            if not db_manager:
                return []
            
            # Build filter conditions
            conditions = []
            if filter:
                if filter.status:
                    conditions.append(f"cf.status = '{filter.status.value}'")
                if filter.business_unit:
                    conditions.append(f"ci.business_unit = '{filter.business_unit}'")
                if filter.ci_class:
                    conditions.append(f"ci.ci_class = '{filter.ci_class}'")
                if filter.min_risk_score:
                    conditions.append(f"cf.risk_score >= {filter.min_risk_score}")
                if filter.max_risk_score:
                    conditions.append(f"cf.risk_score <= {filter.max_risk_score}")
            
            where_clause = " AND " + " AND ".join(conditions) if conditions else ""
            
            # Execute query
            query = f"""
                SELECT cf.*, ci.name as ci_name
                FROM compliance_findings cf
                JOIN configuration_items ci ON cf.ci_id = ci.id
                WHERE 1=1{where_clause}
                ORDER BY cf.created_at DESC
                LIMIT {limit} OFFSET {offset}
            """
            
            findings = await db_manager.execute_query(query)
            
            return [
                ComplianceFinding(
                    id=str(finding['id']),
                    ci_id=finding['ci_id'],
                    evaluated_at=finding['created_at'],
                    status=ComplianceStatus(finding['status']),
                    reason=finding['reason'],
                    risk_score=finding['risk_score'],
                    policy_id=finding.get('policy_id', 'unknown'),
                    remediation=finding.get('remediation'),
                    evidence=str(finding.get('evidence', {}))
                ) for finding in findings
            ]
            
        except Exception as e:
            logger.error(f"Error fetching compliance findings: {e}")
            return []
    
    @strawberry.field
    async def business_units(self) -> List[BusinessUnit]:
        """Get compliance summary by business unit"""
        
        try:
            db_manager = get_db_manager()
            if not db_manager:
                return []
            
            query = """
                SELECT 
                    ci.business_unit,
                    COUNT(*) as system_count,
                    COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN cf.status = 'pass' THEN 1 END) as compliant_count,
                    COUNT(CASE WHEN cf.status = 'warn' THEN 1 END) as warning_count,
                    ROUND(AVG(cf.risk_score), 1) as avg_risk_score
                FROM compliance_findings cf
                JOIN configuration_items ci ON cf.ci_id = ci.id
                WHERE ci.business_unit IS NOT NULL
                GROUP BY ci.business_unit
                ORDER BY avg_risk_score DESC
            """
            
            units = await db_manager.execute_query(query)
            
            return [
                BusinessUnit(
                    name=unit['business_unit'],
                    system_count=unit['system_count'],
                    critical_count=unit['critical_count'],
                    compliant_count=unit['compliant_count'],
                    warning_count=unit['warning_count'],
                    compliance_score=round((unit['compliant_count'] / unit['system_count']) * 100, 1) if unit['system_count'] > 0 else 0,
                    avg_risk_score=float(unit['avg_risk_score'] or 0)
                ) for unit in units
            ]
            
        except Exception as e:
            logger.error(f"Error fetching business units: {e}")
            return []
    
    @strawberry.field
    async def compliance_summary(self) -> ComplianceSummary:
        """Get overall compliance summary"""
        
        try:
            db_manager = get_db_manager()
            if not db_manager:
                return ComplianceSummary(
                    total_systems=0,
                    compliant_systems=0,
                    warning_systems=0,
                    critical_systems=0,
                    compliance_score=0.0,
                    avg_risk_score=0.0,
                    last_updated=datetime.now()
                )
            
            query = """
                SELECT 
                    COUNT(DISTINCT cf.ci_id) as total_systems,
                    COUNT(CASE WHEN cf.status = 'pass' THEN 1 END) as compliant_systems,
                    COUNT(CASE WHEN cf.status = 'warn' THEN 1 END) as warning_systems,
                    COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical_systems,
                    ROUND(AVG(cf.risk_score), 1) as avg_risk_score,
                    MAX(cf.created_at) as last_updated
                FROM compliance_findings cf
            """
            
            result = await db_manager.execute_query(query)
            summary = result[0] if result else {}
            
            total = summary.get('total_systems', 0)
            compliant = summary.get('compliant_systems', 0)
            
            return ComplianceSummary(
                total_systems=total,
                compliant_systems=compliant,
                warning_systems=summary.get('warning_systems', 0),
                critical_systems=summary.get('critical_systems', 0),
                compliance_score=round((compliant / total) * 100, 1) if total > 0 else 0,
                avg_risk_score=float(summary.get('avg_risk_score', 0) or 0),
                last_updated=summary.get('last_updated', datetime.now())
            )
            
        except Exception as e:
            logger.error(f"Error fetching compliance summary: {e}")
            return ComplianceSummary(
                total_systems=0,
                compliant_systems=0,
                warning_systems=0,
                critical_systems=0,
                compliance_score=0.0,
                avg_risk_score=0.0,
                last_updated=datetime.now()
            )
    
    @strawberry.field
    async def ci(self, id: str) -> Optional[CI]:
        """Get a specific CI by ID"""
        
        try:
            db_manager = get_db_manager()
            if db_manager:
                ci_data = await db_manager.get_ci_by_id(id)
                if ci_data:
                    return CI(
                        id=ci_data['id'],
                        name=ci_data['name'],
                        ci_class=ci_data['ci_class'],
                        business_unit=ci_data.get('business_unit'),
                        owner=ci_data.get('owner'),
                        ip_address=ci_data.get('ip_address'),
                        location=ci_data.get('location'),
                        environment=ci_data.get('environment'),
                        criticality=ci_data.get('criticality'),
                        tags=str(ci_data.get('tags', {}))
                    )
        except Exception as e:
            logger.error(f"Error fetching CI {id}: {e}")
        
        return None

# Mutations
@strawberry.type
class Mutation:
    
    @strawberry.field
    async def start_compliance_scan(
        self, 
        ci_ids: Optional[List[str]] = None,
        business_unit: Optional[str] = None
    ) -> ScanStatus:
        """Start a new compliance scan"""
        
        try:
            # Generate scan ID
            scan_id = f"gql_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Mock scan status (would integrate with actual scanner)
            return ScanStatus(
                scan_id=scan_id,
                status="started",
                progress=0,
                total_systems=len(ci_ids) if ci_ids else 10,
                completed_systems=0,
                started_at=datetime.now(),
                estimated_completion=None
            )
            
        except Exception as e:
            logger.error(f"Error starting compliance scan: {e}")
            return ScanStatus(
                scan_id="error",
                status="failed",
                progress=0,
                total_systems=0,
                completed_systems=0,
                started_at=datetime.now(),
                estimated_completion=None
            )

# Subscriptions (for real-time updates)
@strawberry.type
class Subscription:
    
    @strawberry.subscription
    async def compliance_updates(self) -> ComplianceFinding:
        """Subscribe to real-time compliance finding updates"""
        
        # Mock subscription - would integrate with actual event system
        while True:
            await asyncio.sleep(30)  # Poll every 30 seconds
            
            # Yield latest finding (simplified example)
            yield ComplianceFinding(
                id=f"sub_{datetime.now().timestamp()}",
                ci_id="demo-ci-001",
                evaluated_at=datetime.now(),
                status=ComplianceStatus.WARN,
                reason="Real-time update example",
                risk_score=50,
                policy_id="baseline",
                remediation="Check system status",
                evidence="{}"
            )

# Create GraphQL schema
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription
)