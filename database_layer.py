#!/usr/bin/env python3
"""
Enterprise CMDB Compliance Tool - PostgreSQL Database Layer
Production-ready database schema and operations for persistent storage
"""

import asyncio
import asyncpg
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from contextlib import asynccontextmanager
import uuid

# Database models and schemas
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

class ConnectorType(Enum):
    SSH = "ssh"
    WINRM = "winrm"
    NAPALM = "napalm"
    SNMP = "snmp"
    NMAP = "nmap"

@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 5432
    database: str = "cmdb_compliance"
    username: str = "compliance_user"
    password: str = "secure_password"
    pool_min_size: int = 5
    pool_max_size: int = 20
    command_timeout: int = 30

class PostgreSQLDatabase:
    """Production PostgreSQL database layer for CMDB compliance data"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.pool: Optional[asyncpg.Pool] = None
        self.connection_string = (
            f"postgresql://{config.username}:{config.password}@"
            f"{config.host}:{config.port}/{config.database}"
        )
    
    async def initialize(self):
        """Initialize database connection pool and create tables"""
        try:
            # Create connection pool
            self.pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=self.config.pool_min_size,
                max_size=self.config.pool_max_size,
                command_timeout=self.config.command_timeout
            )
            
            logger.info(f"✅ Connected to PostgreSQL: {self.config.host}:{self.config.port}")
            
            # Create database schema
            await self.create_schema()
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            raise
    
    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("🔌 Database connection pool closed")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool"""
        if not self.pool:
            raise RuntimeError("Database not initialized")
        
        async with self.pool.acquire() as connection:
            yield connection
    
    async def create_schema(self):
        """Create database tables and indexes"""
        
        schema_sql = """
        -- Configuration Items (CIs) table
        CREATE TABLE IF NOT EXISTS configuration_items (
            id VARCHAR(255) PRIMARY KEY,
            sn_sys_id VARCHAR(255) UNIQUE,
            name VARCHAR(255) NOT NULL,
            ci_class VARCHAR(100) NOT NULL,
            business_unit VARCHAR(100),
            owner VARCHAR(255),
            ip_address INET,
            fqdn VARCHAR(255),
            operational_status VARCHAR(50),
            environment VARCHAR(50),
            location VARCHAR(255),
            tags JSONB DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- OS Facts table
        CREATE TABLE IF NOT EXISTS os_facts (
            id SERIAL PRIMARY KEY,
            ci_id VARCHAR(255) REFERENCES configuration_items(id) ON DELETE CASCADE,
            collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
            product VARCHAR(255),
            version VARCHAR(255),
            edition VARCHAR(255),
            kernel VARCHAR(255),
            connector_used VARCHAR(50) NOT NULL,
            confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
            raw_data JSONB DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Lifecycle Information table
        CREATE TABLE IF NOT EXISTS lifecycle_info (
            id SERIAL PRIMARY KEY,
            product VARCHAR(255) NOT NULL,
            version VARCHAR(255) NOT NULL,
            eol_date DATE,
            eos_date DATE,
            lts BOOLEAN DEFAULT FALSE,
            latest_version VARCHAR(255),
            source VARCHAR(100) NOT NULL,
            retrieved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(product, version)
        );
        
        -- Compliance Findings table
        CREATE TABLE IF NOT EXISTS compliance_findings (
            id SERIAL PRIMARY KEY,
            ci_id VARCHAR(255) REFERENCES configuration_items(id) ON DELETE CASCADE,
            evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
            status VARCHAR(50) NOT NULL CHECK (status IN ('pass', 'warn', 'fail', 'unknown')),
            reason TEXT NOT NULL,
            evidence JSONB DEFAULT '{}',
            policy_id VARCHAR(255),
            risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
            remediation TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Compliance Scans table
        CREATE TABLE IF NOT EXISTS compliance_scans (
            id VARCHAR(255) PRIMARY KEY,
            started_at TIMESTAMP WITH TIME ZONE NOT NULL,
            completed_at TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'cancelled')),
            scan_config JSONB NOT NULL,
            progress DECIMAL(5,2) DEFAULT 0,
            total_targets INTEGER DEFAULT 0,
            completed_targets INTEGER DEFAULT 0,
            errors JSONB DEFAULT '[]',
            created_by VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Scan Results table (link scans to findings)
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            scan_id VARCHAR(255) REFERENCES compliance_scans(id) ON DELETE CASCADE,
            ci_id VARCHAR(255) REFERENCES configuration_items(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES compliance_findings(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Compliance Policies table
        CREATE TABLE IF NOT EXISTS compliance_policies (
            id VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            policy_content TEXT NOT NULL,
            policy_type VARCHAR(100) NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            created_by VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- AI Assistant Interactions table
        CREATE TABLE IF NOT EXISTS ai_interactions (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255),
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            context_data JSONB DEFAULT '{}',
            sources JSONB DEFAULT '[]',
            model_used VARCHAR(100),
            response_time_ms INTEGER,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Indexes for performance
        CREATE INDEX IF NOT EXISTS idx_ci_business_unit ON configuration_items(business_unit);
        CREATE INDEX IF NOT EXISTS idx_ci_class ON configuration_items(ci_class);
        CREATE INDEX IF NOT EXISTS idx_ci_ip_address ON configuration_items(ip_address);
        CREATE INDEX IF NOT EXISTS idx_os_facts_ci_id ON os_facts(ci_id);
        CREATE INDEX IF NOT EXISTS idx_os_facts_collected_at ON os_facts(collected_at);
        CREATE INDEX IF NOT EXISTS idx_lifecycle_product_version ON lifecycle_info(product, version);
        CREATE INDEX IF NOT EXISTS idx_findings_ci_id ON compliance_findings(ci_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON compliance_findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_evaluated_at ON compliance_findings(evaluated_at);
        CREATE INDEX IF NOT EXISTS idx_scan_status ON compliance_scans(status);
        CREATE INDEX IF NOT EXISTS idx_scan_started_at ON compliance_scans(started_at);
        
        -- Functions and triggers for updated_at
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        
        DROP TRIGGER IF EXISTS update_configuration_items_updated_at ON configuration_items;
        CREATE TRIGGER update_configuration_items_updated_at
            BEFORE UPDATE ON configuration_items
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            
        DROP TRIGGER IF EXISTS update_compliance_policies_updated_at ON compliance_policies;
        CREATE TRIGGER update_compliance_policies_updated_at
            BEFORE UPDATE ON compliance_policies
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """
        
        async with self.get_connection() as conn:
            await conn.execute(schema_sql)
            logger.info("✅ Database schema created/updated successfully")
    
    # CI Management Methods
    async def save_ci(self, ci_data: Dict[str, Any]) -> str:
        """Save or update a Configuration Item"""
        
        query = """
        INSERT INTO configuration_items (
            id, sn_sys_id, name, ci_class, business_unit, owner,
            ip_address, fqdn, operational_status, environment, location, tags
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (id) DO UPDATE SET
            sn_sys_id = EXCLUDED.sn_sys_id,
            name = EXCLUDED.name,
            ci_class = EXCLUDED.ci_class,
            business_unit = EXCLUDED.business_unit,
            owner = EXCLUDED.owner,
            ip_address = EXCLUDED.ip_address,
            fqdn = EXCLUDED.fqdn,
            operational_status = EXCLUDED.operational_status,
            environment = EXCLUDED.environment,
            location = EXCLUDED.location,
            tags = EXCLUDED.tags,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id
        """
        
        async with self.get_connection() as conn:
            ci_id = await conn.fetchval(
                query,
                ci_data.get('id'),
                ci_data.get('sn_sys_id'),
                ci_data.get('name'),
                ci_data.get('ci_class'),
                ci_data.get('business_unit'),
                ci_data.get('owner'),
                ci_data.get('ip_address'),
                ci_data.get('fqdn'),
                ci_data.get('operational_status'),
                ci_data.get('environment'),
                ci_data.get('location'),
                json.dumps(ci_data.get('tags', {}))
            )
            
            logger.debug(f"Saved CI: {ci_id}")
            return ci_id
    
    async def get_cis(
        self, 
        ci_classes: List[str] = None,
        business_units: List[str] = None,
        limit: int = None,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve Configuration Items with filtering"""
        
        where_clauses = []
        params = []
        param_count = 0
        
        if ci_classes:
            param_count += 1
            where_clauses.append(f"ci_class = ANY(${param_count})")
            params.append(ci_classes)
        
        if business_units:
            param_count += 1
            where_clauses.append(f"business_unit = ANY(${param_count})")
            params.append(business_units)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        limit_sql = f"LIMIT {limit}" if limit else ""
        offset_sql = f"OFFSET {offset}" if offset else ""
        
        query = f"""
        SELECT id, sn_sys_id, name, ci_class, business_unit, owner,
               ip_address, fqdn, operational_status, environment, location,
               tags, created_at, updated_at
        FROM configuration_items
        {where_sql}
        ORDER BY created_at DESC
        {limit_sql} {offset_sql}
        """
        
        async with self.get_connection() as conn:
            rows = await conn.fetch(query, *params)
            
            return [dict(row) for row in rows]
    
    # OS Facts Methods
    async def save_os_facts(self, os_facts_data: Dict[str, Any]) -> int:
        """Save OS facts for a CI"""
        
        query = """
        INSERT INTO os_facts (
            ci_id, collected_at, product, version, edition, kernel,
            connector_used, confidence, raw_data
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        """
        
        async with self.get_connection() as conn:
            facts_id = await conn.fetchval(
                query,
                os_facts_data.get('ci_id'),
                os_facts_data.get('collected_at', datetime.now()),
                os_facts_data.get('product'),
                os_facts_data.get('version'),
                os_facts_data.get('edition'),
                os_facts_data.get('kernel'),
                os_facts_data.get('connector_used'),
                os_facts_data.get('confidence'),
                json.dumps(os_facts_data.get('raw_data', {}))
            )
            
            logger.debug(f"Saved OS facts: {facts_id}")
            return facts_id
    
    async def get_latest_os_facts(self, ci_id: str) -> Optional[Dict[str, Any]]:
        """Get the most recent OS facts for a CI"""
        
        query = """
        SELECT id, ci_id, collected_at, product, version, edition, kernel,
               connector_used, confidence, raw_data, created_at
        FROM os_facts
        WHERE ci_id = $1
        ORDER BY collected_at DESC
        LIMIT 1
        """
        
        async with self.get_connection() as conn:
            row = await conn.fetchrow(query, ci_id)
            return dict(row) if row else None
    
    # Compliance Findings Methods
    async def save_compliance_finding(self, finding_data: Dict[str, Any]) -> int:
        """Save a compliance finding"""
        
        query = """
        INSERT INTO compliance_findings (
            ci_id, evaluated_at, status, reason, evidence,
            policy_id, risk_score, remediation
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        """
        
        async with self.get_connection() as conn:
            finding_id = await conn.fetchval(
                query,
                finding_data.get('ci_id'),
                finding_data.get('evaluated_at', datetime.now()),
                finding_data.get('status'),
                finding_data.get('reason'),
                json.dumps(finding_data.get('evidence', {})),
                finding_data.get('policy_id'),
                finding_data.get('risk_score'),
                finding_data.get('remediation')
            )
            
            logger.debug(f"Saved compliance finding: {finding_id}")
            return finding_id
    
    async def get_compliance_findings(
        self,
        ci_ids: List[str] = None,
        statuses: List[str] = None,
        business_units: List[str] = None,
        days_back: int = 30,
        limit: int = None
    ) -> List[Dict[str, Any]]:
        """Get compliance findings with filtering"""
        
        where_clauses = ["cf.evaluated_at >= $1"]
        params = [datetime.now() - timedelta(days=days_back)]
        param_count = 1
        
        if ci_ids:
            param_count += 1
            where_clauses.append(f"cf.ci_id = ANY(${param_count})")
            params.append(ci_ids)
        
        if statuses:
            param_count += 1
            where_clauses.append(f"cf.status = ANY(${param_count})")
            params.append(statuses)
        
        if business_units:
            param_count += 1
            where_clauses.append(f"ci.business_unit = ANY(${param_count})")
            params.append(business_units)
        
        where_sql = "WHERE " + " AND ".join(where_clauses)
        limit_sql = f"LIMIT {limit}" if limit else ""
        
        query = f"""
        SELECT cf.id, cf.ci_id, ci.name as ci_name, ci.business_unit,
               cf.evaluated_at, cf.status, cf.reason, cf.evidence,
               cf.policy_id, cf.risk_score, cf.remediation, cf.created_at
        FROM compliance_findings cf
        JOIN configuration_items ci ON cf.ci_id = ci.id
        {where_sql}
        ORDER BY cf.evaluated_at DESC
        {limit_sql}
        """
        
        async with self.get_connection() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    # Scan Management Methods
    async def create_scan(self, scan_data: Dict[str, Any]) -> str:
        """Create a new compliance scan record"""
        
        scan_id = scan_data.get('id', str(uuid.uuid4()))
        
        query = """
        INSERT INTO compliance_scans (
            id, started_at, status, scan_config, total_targets, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        """
        
        async with self.get_connection() as conn:
            result_id = await conn.fetchval(
                query,
                scan_id,
                scan_data.get('started_at', datetime.now()),
                scan_data.get('status', 'running'),
                json.dumps(scan_data.get('scan_config', {})),
                scan_data.get('total_targets', 0),
                scan_data.get('created_by')
            )
            
            logger.info(f"Created scan: {result_id}")
            return result_id
    
    async def update_scan_progress(
        self,
        scan_id: str,
        progress: float,
        completed_targets: int,
        status: str = None
    ):
        """Update scan progress"""
        
        if status:
            query = """
            UPDATE compliance_scans 
            SET progress = $2, completed_targets = $3, status = $4,
                completed_at = CASE WHEN $4 IN ('completed', 'failed', 'cancelled') 
                                   THEN CURRENT_TIMESTAMP ELSE completed_at END
            WHERE id = $1
            """
            params = [scan_id, progress, completed_targets, status]
        else:
            query = """
            UPDATE compliance_scans 
            SET progress = $2, completed_targets = $3
            WHERE id = $1
            """
            params = [scan_id, progress, completed_targets]
        
        async with self.get_connection() as conn:
            await conn.execute(query, *params)
    
    # Analytics and Reporting Methods
    async def get_compliance_summary(
        self,
        business_units: List[str] = None,
        days_back: int = 7
    ) -> Dict[str, Any]:
        """Get compliance summary statistics"""
        
        where_clauses = ["cf.evaluated_at >= $1"]
        params = [datetime.now() - timedelta(days=days_back)]
        param_count = 1
        
        if business_units:
            param_count += 1
            where_clauses.append(f"ci.business_unit = ANY(${param_count})")
            params.append(business_units)
        
        where_sql = "WHERE " + " AND ".join(where_clauses)
        
        query = f"""
        SELECT 
            COUNT(*) as total_findings,
            COUNT(DISTINCT cf.ci_id) as total_systems,
            COUNT(CASE WHEN cf.status = 'pass' THEN 1 END) as compliant,
            COUNT(CASE WHEN cf.status = 'warn' THEN 1 END) as warnings,
            COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical,
            COUNT(CASE WHEN cf.status = 'unknown' THEN 1 END) as unknown,
            AVG(cf.risk_score) as avg_risk_score,
            MAX(cf.risk_score) as max_risk_score
        FROM compliance_findings cf
        JOIN configuration_items ci ON cf.ci_id = ci.id
        {where_sql}
        """
        
        async with self.get_connection() as conn:
            row = await conn.fetchrow(query, *params)
            
            result = dict(row) if row else {}
            
            # Calculate compliance score
            total = result.get('total_findings', 0)
            compliant = result.get('compliant', 0)
            compliance_score = (compliant / total * 100) if total > 0 else 0
            
            result['compliance_score'] = round(compliance_score, 1)
            result['generated_at'] = datetime.now().isoformat()
            
            return result
    
    # AI Interaction Logging
    async def log_ai_interaction(
        self,
        session_id: str,
        question: str,
        answer: str,
        context_data: Dict[str, Any] = None,
        sources: List[str] = None,
        model_used: str = None,
        response_time_ms: int = None
    ) -> int:
        """Log AI assistant interaction for analytics"""
        
        query = """
        INSERT INTO ai_interactions (
            session_id, question, answer, context_data, sources,
            model_used, response_time_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        """
        
        async with self.get_connection() as conn:
            interaction_id = await conn.fetchval(
                query,
                session_id,
                question,
                answer,
                json.dumps(context_data or {}),
                json.dumps(sources or []),
                model_used,
                response_time_ms
            )
            
            return interaction_id

# Database manager for application use
class DatabaseManager:
    """High-level database manager for the compliance application"""
    
    def __init__(self, config: DatabaseConfig):
        self.db = PostgreSQLDatabase(config)
        self._initialized = False
    
    async def initialize(self):
        """Initialize database connection"""
        if not self._initialized:
            await self.db.initialize()
            self._initialized = True
    
    async def close(self):
        """Close database connection"""
        if self._initialized:
            await self.db.close()
            self._initialized = False
    
    async def store_servicenow_data(self, ci_data: List[Dict[str, Any]]):
        """Store ServiceNow CI data in database"""
        for ci in ci_data:
            await self.db.save_ci(ci)
        
        logger.info(f"Stored {len(ci_data)} CIs from ServiceNow")
    
    async def store_scan_results(
        self,
        scan_id: str,
        ci_id: str,
        os_facts: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ):
        """Store complete scan results for a CI"""
        
        # Store OS facts
        os_facts['ci_id'] = ci_id
        await self.db.save_os_facts(os_facts)
        
        # Store compliance findings
        for finding in findings:
            finding['ci_id'] = ci_id
            finding_id = await self.db.save_compliance_finding(finding)
            
            # Link to scan (scan_results table would be populated here)
        
        logger.debug(f"Stored scan results for CI: {ci_id}")
    
    async def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for compliance dashboard"""
        
        # Get summary statistics
        summary = await self.db.get_compliance_summary()
        
        # Get recent findings
        recent_findings = await self.db.get_compliance_findings(limit=10)
        
        # Get CI breakdown by business unit
        cis = await self.db.get_cis()
        bu_breakdown = {}
        for ci in cis:
            bu = ci.get('business_unit', 'Unknown')
            bu_breakdown[bu] = bu_breakdown.get(bu, 0) + 1
        
        return {
            'summary': summary,
            'recent_findings': recent_findings,
            'business_unit_breakdown': bu_breakdown,
            'total_systems': len(cis)
        }

# Example usage and testing
async def demo_database_operations():
    """Demonstrate database operations"""
    
    config = DatabaseConfig(
        host="localhost",
        port=5432,
        database="cmdb_compliance_demo",
        username="postgres",
        password="password"
    )
    
    db_manager = DatabaseManager(config)
    
    try:
        await db_manager.initialize()
        print("✅ Database initialized")
        
        # Demo CI data
        demo_ci = {
            'id': 'demo_ci_001',
            'sn_sys_id': 'sys_001',
            'name': 'demo-server-01',
            'ci_class': 'cmdb_ci_win_server',
            'business_unit': 'Finance',
            'owner': 'admin@company.com',
            'ip_address': '10.1.1.100',
            'tags': {'environment': 'production', 'criticality': 'high'}
        }
        
        # Store CI
        await db_manager.db.save_ci(demo_ci)
        print("✅ CI saved")
        
        # Store OS facts
        os_facts = {
            'ci_id': 'demo_ci_001',
            'collected_at': datetime.now(),
            'product': 'windows-server',
            'version': '2019',
            'connector_used': 'winrm',
            'confidence': 0.98
        }
        
        await db_manager.db.save_os_facts(os_facts)
        print("✅ OS facts saved")
        
        # Store compliance finding
        finding = {
            'ci_id': 'demo_ci_001',
            'evaluated_at': datetime.now(),
            'status': 'pass',
            'reason': 'Compliant - Windows Server 2019',
            'policy_id': 'baseline',
            'risk_score': 0
        }
        
        await db_manager.db.save_compliance_finding(finding)
        print("✅ Compliance finding saved")
        
        # Get dashboard data
        dashboard_data = await db_manager.get_compliance_dashboard_data()
        print("📊 Dashboard data:", json.dumps(dashboard_data, indent=2, default=str))
        
    except Exception as e:
        print(f"❌ Database demo failed: {e}")
    finally:
        await db_manager.close()

if __name__ == "__main__":
    asyncio.run(demo_database_operations())