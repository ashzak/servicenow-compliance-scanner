#!/usr/bin/env python3
"""
PostgreSQL Setup Script for Enterprise CMDB Compliance Tool
Automated database setup and configuration
"""

import asyncio
import asyncpg
import json
import logging
import os
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PostgreSQLSetup:
    """Automated PostgreSQL setup for compliance tool"""
    
    def __init__(self):
        self.admin_config = {
            'host': os.getenv('POSTGRES_HOST', 'localhost'),
            'port': int(os.getenv('POSTGRES_PORT', 5432)),
            'user': os.getenv('POSTGRES_ADMIN_USER', 'postgres'),
            'password': os.getenv('POSTGRES_ADMIN_PASSWORD', ''),
            'database': 'postgres'  # Connect to default DB for admin tasks
        }
        
        self.app_config = {
            'host': os.getenv('POSTGRES_HOST', 'localhost'),
            'port': int(os.getenv('POSTGRES_PORT', 5432)),
            'database': 'cmdb_compliance',
            'user': 'compliance_user',
            'password': 'secure_compliance_pass_2024!'
        }
    
    async def check_postgres_connection(self):
        """Check if PostgreSQL is accessible"""
        try:
            conn = await asyncpg.connect(
                host=self.admin_config['host'],
                port=self.admin_config['port'],
                user=self.admin_config['user'],
                password=self.admin_config['password'],
                database=self.admin_config['database']
            )
            
            version = await conn.fetchval('SELECT version()')
            await conn.close()
            
            logger.info(f"✅ PostgreSQL connection successful!")
            logger.info(f"📊 Version: {version}")
            return True
            
        except Exception as e:
            logger.error(f"❌ PostgreSQL connection failed: {e}")
            logger.error("🔧 Please ensure PostgreSQL is installed and running")
            return False
    
    async def create_database_and_user(self):
        """Create application database and user"""
        try:
            # Connect as admin
            conn = await asyncpg.connect(
                host=self.admin_config['host'],
                port=self.admin_config['port'],
                user=self.admin_config['user'],
                password=self.admin_config['password'],
                database=self.admin_config['database']
            )
            
            # Check if database exists
            db_exists = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1",
                self.app_config['database']
            )
            
            if not db_exists:
                # Create database
                await conn.execute(f'CREATE DATABASE {self.app_config["database"]}')
                logger.info(f"✅ Created database: {self.app_config['database']}")
            else:
                logger.info(f"📊 Database already exists: {self.app_config['database']}")
            
            # Check if user exists
            user_exists = await conn.fetchval(
                "SELECT 1 FROM pg_user WHERE usename = $1",
                self.app_config['user']
            )
            
            if not user_exists:
                # Create user
                await conn.execute(f"""
                    CREATE USER {self.app_config['user']} 
                    WITH PASSWORD '{self.app_config['password']}'
                """)
                logger.info(f"✅ Created user: {self.app_config['user']}")
            else:
                logger.info(f"👤 User already exists: {self.app_config['user']}")
            
            # Grant privileges
            await conn.execute(f"""
                GRANT ALL PRIVILEGES ON DATABASE {self.app_config['database']} 
                TO {self.app_config['user']}
            """)
            
            await conn.close()
            logger.info("✅ Database and user setup completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create database/user: {e}")
            return False
    
    async def create_schema(self):
        """Create application schema and tables"""
        try:
            # Connect to application database
            conn = await asyncpg.connect(
                host=self.app_config['host'],
                port=self.app_config['port'],
                user=self.app_config['user'],
                password=self.app_config['password'],
                database=self.app_config['database']
            )
            
            # Read schema from database_layer.py or create inline
            schema_sql = await self._get_schema_sql()
            
            # Execute schema creation
            await conn.execute(schema_sql)
            
            await conn.close()
            logger.info("✅ Database schema created successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create schema: {e}")
            return False
    
    async def _get_schema_sql(self):
        """Get the database schema SQL"""
        return """
        -- Enable UUID extension
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        
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
        
        -- Scan Results table
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
        
        -- Create indexes for performance
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
        
        -- Function for updating timestamps
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        
        -- Triggers for updated_at
        DROP TRIGGER IF EXISTS update_configuration_items_updated_at ON configuration_items;
        CREATE TRIGGER update_configuration_items_updated_at
            BEFORE UPDATE ON configuration_items
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            
        DROP TRIGGER IF EXISTS update_compliance_policies_updated_at ON compliance_policies;
        CREATE TRIGGER update_compliance_policies_updated_at
            BEFORE UPDATE ON compliance_policies
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """
    
    async def insert_sample_data(self):
        """Insert sample data for testing"""
        try:
            conn = await asyncpg.connect(
                host=self.app_config['host'],
                port=self.app_config['port'],
                user=self.app_config['user'],
                password=self.app_config['password'],
                database=self.app_config['database']
            )
            
            # Sample CI data
            sample_cis = [
                {
                    'id': 'ci_001',
                    'sn_sys_id': 'sys_001',
                    'name': 'legacy-dc-01',
                    'ci_class': 'cmdb_ci_win_server',
                    'business_unit': 'Finance',
                    'owner': 'john.doe@company.com',
                    'ip_address': '10.1.1.10',
                    'environment': 'production'
                },
                {
                    'id': 'ci_002',
                    'sn_sys_id': 'sys_002',
                    'name': 'web-app-02',
                    'ci_class': 'cmdb_ci_unix_server',
                    'business_unit': 'Marketing',
                    'owner': 'jane.smith@company.com',
                    'ip_address': '10.1.2.20',
                    'environment': 'production'
                },
                {
                    'id': 'ci_003',
                    'sn_sys_id': 'sys_003',
                    'name': 'app-server-03',
                    'ci_class': 'cmdb_ci_win_server',
                    'business_unit': 'Engineering',
                    'owner': 'bob.wilson@company.com',
                    'ip_address': '10.1.3.30',
                    'environment': 'production'
                }
            ]
            
            # Insert CIs
            for ci in sample_cis:
                await conn.execute("""
                    INSERT INTO configuration_items (
                        id, sn_sys_id, name, ci_class, business_unit, owner, ip_address, environment, tags
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (id) DO NOTHING
                """, ci['id'], ci['sn_sys_id'], ci['name'], ci['ci_class'], 
                    ci['business_unit'], ci['owner'], ci['ip_address'], ci['environment'], '{}')
            
            # Sample lifecycle data
            lifecycle_data = [
                ('windows-server', '2008-r2', '2020-01-14', '2023-01-10', False, '2022', 'endoflife.date'),
                ('ubuntu', '18.04', '2023-05-31', '2028-05-31', True, '22.04', 'endoflife.date'),
                ('windows-server', '2022', '2031-10-14', '2033-10-14', False, '2022', 'endoflife.date')
            ]
            
            for product, version, eol_date, eos_date, lts, latest, source in lifecycle_data:
                await conn.execute("""
                    INSERT INTO lifecycle_info (product, version, eol_date, eos_date, lts, latest_version, source)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (product, version) DO NOTHING
                """, product, version, eol_date, eos_date, lts, latest, source)
            
            # Sample OS facts
            os_facts_data = [
                ('ci_001', 'windows-server', '2008-r2', 'datacenter', 'winrm', 0.95),
                ('ci_002', 'ubuntu', '18.04', '', 'ssh', 0.98),
                ('ci_003', 'windows-server', '2022', 'standard', 'winrm', 0.99)
            ]
            
            for ci_id, product, version, edition, connector, confidence in os_facts_data:
                await conn.execute("""
                    INSERT INTO os_facts (ci_id, collected_at, product, version, edition, connector_used, confidence, raw_data)
                    VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, $5, $6, '{}')
                """, ci_id, product, version, edition, connector, confidence)
            
            # Sample compliance findings
            findings_data = [
                ('ci_001', 'fail', 'Past End-of-Life (2020-01-14)', 90, 'Upgrade to Windows Server 2019 or newer immediately'),
                ('ci_002', 'warn', 'EOL in 45 days', 60, 'Plan upgrade to Ubuntu 22.04 LTS within maintenance window'),
                ('ci_003', 'pass', 'Compliant - Windows Server 2022', 0, None)
            ]
            
            for ci_id, status, reason, risk_score, remediation in findings_data:
                await conn.execute("""
                    INSERT INTO compliance_findings (ci_id, evaluated_at, status, reason, risk_score, remediation, policy_id, evidence)
                    VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, $5, 'baseline', '{}')
                """, ci_id, status, reason, risk_score, remediation)
            
            await conn.close()
            logger.info("✅ Sample data inserted successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to insert sample data: {e}")
            return False
    
    async def test_database_operations(self):
        """Test basic database operations"""
        try:
            conn = await asyncpg.connect(
                host=self.app_config['host'],
                port=self.app_config['port'],
                user=self.app_config['user'],
                password=self.app_config['password'],
                database=self.app_config['database']
            )
            
            # Test queries
            ci_count = await conn.fetchval("SELECT COUNT(*) FROM configuration_items")
            findings_count = await conn.fetchval("SELECT COUNT(*) FROM compliance_findings")
            
            # Test complex query
            compliance_summary = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_findings,
                    COUNT(DISTINCT cf.ci_id) as total_systems,
                    COUNT(CASE WHEN cf.status = 'pass' THEN 1 END) as compliant,
                    COUNT(CASE WHEN cf.status = 'warn' THEN 1 END) as warnings,
                    COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical,
                    AVG(cf.risk_score) as avg_risk_score
                FROM compliance_findings cf
                JOIN configuration_items ci ON cf.ci_id = ci.id
            """)
            
            await conn.close()
            
            logger.info("🧪 Database Test Results:")
            logger.info(f"   📊 CIs: {ci_count}")
            logger.info(f"   🔍 Findings: {findings_count}")
            logger.info(f"   📈 Compliance Summary:")
            logger.info(f"      - Total Systems: {compliance_summary['total_systems']}")
            logger.info(f"      - Compliant: {compliance_summary['compliant']}")
            logger.info(f"      - Warnings: {compliance_summary['warnings']}")
            logger.info(f"      - Critical: {compliance_summary['critical']}")
            logger.info(f"      - Avg Risk Score: {compliance_summary['avg_risk_score']:.1f}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Database test failed: {e}")
            return False
    
    def generate_config_file(self):
        """Generate database configuration file"""
        config = {
            "database": {
                "host": self.app_config['host'],
                "port": self.app_config['port'],
                "database": self.app_config['database'],
                "username": self.app_config['user'],
                "password": self.app_config['password'],
                "pool_min_size": 5,
                "pool_max_size": 20,
                "command_timeout": 30
            }
        }
        
        config_file = Path(__file__).parent / "database_config.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"✅ Database config saved to: {config_file}")
        
        # Also generate environment variables
        env_file = Path(__file__).parent / ".env.database"
        with open(env_file, 'w') as f:
            f.write(f"POSTGRES_HOST={self.app_config['host']}\n")
            f.write(f"POSTGRES_PORT={self.app_config['port']}\n")
            f.write(f"POSTGRES_DATABASE={self.app_config['database']}\n")
            f.write(f"POSTGRES_USERNAME={self.app_config['user']}\n")
            f.write(f"POSTGRES_PASSWORD={self.app_config['password']}\n")
        
        logger.info(f"✅ Environment config saved to: {env_file}")
    
    async def run_full_setup(self):
        """Run complete PostgreSQL setup"""
        logger.info("🚀 Starting PostgreSQL setup for CMDB Compliance Tool...")
        
        # Step 1: Check connection
        if not await self.check_postgres_connection():
            logger.error("❌ Setup failed: Cannot connect to PostgreSQL")
            return False
        
        # Step 2: Create database and user
        if not await self.create_database_and_user():
            logger.error("❌ Setup failed: Could not create database/user")
            return False
        
        # Step 3: Create schema
        if not await self.create_schema():
            logger.error("❌ Setup failed: Could not create schema")
            return False
        
        # Step 4: Insert sample data
        if not await self.insert_sample_data():
            logger.error("❌ Setup failed: Could not insert sample data")
            return False
        
        # Step 5: Test operations
        if not await self.test_database_operations():
            logger.error("❌ Setup failed: Database tests failed")
            return False
        
        # Step 6: Generate config files
        self.generate_config_file()
        
        logger.info("🎉 PostgreSQL setup completed successfully!")
        logger.info("📋 Next steps:")
        logger.info("   1. Review the generated database_config.json")
        logger.info("   2. Update your application to use the new database")
        logger.info("   3. Test the live database integration")
        
        return True

def print_installation_instructions():
    """Print PostgreSQL installation instructions"""
    logger.info("📋 PostgreSQL Installation Instructions:")
    logger.info("")
    logger.info("🍎 macOS (Homebrew):")
    logger.info("   brew install postgresql@14")
    logger.info("   brew services start postgresql@14")
    logger.info("")
    logger.info("🐧 Ubuntu/Debian:")
    logger.info("   sudo apt update")
    logger.info("   sudo apt install postgresql postgresql-contrib")
    logger.info("   sudo systemctl start postgresql")
    logger.info("")
    logger.info("🎩 RHEL/CentOS:")
    logger.info("   sudo dnf install postgresql-server postgresql-contrib")
    logger.info("   sudo postgresql-setup --initdb")
    logger.info("   sudo systemctl start postgresql")
    logger.info("")
    logger.info("🐳 Docker:")
    logger.info("   docker run -d --name postgres-compliance \\")
    logger.info("     -e POSTGRES_PASSWORD=mypassword \\")
    logger.info("     -p 5432:5432 postgres:14")
    logger.info("")

async def main():
    """Main setup function"""
    
    print("🏢 Enterprise CMDB Compliance Tool - PostgreSQL Setup")
    print("=" * 60)
    
    # Check if PostgreSQL connection info is provided
    admin_password = os.getenv('POSTGRES_ADMIN_PASSWORD')
    if not admin_password:
        print("⚠️  PostgreSQL admin password not provided")
        print("   Set POSTGRES_ADMIN_PASSWORD environment variable")
        print("   Example: export POSTGRES_ADMIN_PASSWORD='your_postgres_password'")
        print("")
        print_installation_instructions()
        
        # Try with empty password (default for some installations)
        response = input("🤔 Try setup with empty password? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Run setup
    setup = PostgreSQLSetup()
    success = await setup.run_full_setup()
    
    if success:
        print("\n🎉 Setup completed! Your database is ready.")
        print(f"🔗 Connection: postgresql://{setup.app_config['user']}@{setup.app_config['host']}:{setup.app_config['port']}/{setup.app_config['database']}")
    else:
        print("\n❌ Setup failed. Please check the logs above.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Setup cancelled by user")
    except Exception as e:
        logger.error(f"❌ Setup failed with error: {e}")
        sys.exit(1)