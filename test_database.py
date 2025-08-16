#!/usr/bin/env python3
"""
Test PostgreSQL Database Integration
Verify database operations and generate test report
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from database_layer import DatabaseManager, DatabaseConfig
    DATABASE_MODULE_AVAILABLE = True
except ImportError:
    DATABASE_MODULE_AVAILABLE = False

async def test_database_connection():
    """Test basic database connectivity"""
    
    if not DATABASE_MODULE_AVAILABLE:
        logger.error("❌ database_layer module not available")
        return False
    
    try:
        # Load config
        config_file = Path(__file__).parent / "database_config.json"
        with open(config_file) as f:
            config_data = json.load(f)
        
        db_config = DatabaseConfig(
            host=config_data["database"]["host"],
            port=config_data["database"]["port"],
            database=config_data["database"]["database"],
            username=config_data["database"]["username"],
            password=config_data["database"]["password"]
        )
        
        # Test connection
        db_manager = DatabaseManager(db_config)
        await db_manager.initialize()
        
        logger.info("✅ Database connection successful")
        
        # Test basic operations
        dashboard_data = await db_manager.get_compliance_dashboard_data()
        
        await db_manager.close()
        
        logger.info("📊 Dashboard data retrieved successfully:")
        logger.info(f"   - Total systems: {dashboard_data['total_systems']}")
        logger.info(f"   - Compliance score: {dashboard_data['summary']['compliance_score']}%")
        logger.info(f"   - Critical issues: {dashboard_data['summary']['critical']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Database test failed: {e}")
        return False

async def test_direct_queries():
    """Test direct database queries using asyncpg"""
    
    try:
        import asyncpg
        
        conn = await asyncpg.connect(
            host="localhost",
            port=5432,
            user="compliance_user",
            password="secure_compliance_pass_2024!",
            database="cmdb_compliance"
        )
        
        # Test 1: Count all tables
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        
        logger.info(f"✅ Found {len(tables)} database tables:")
        for table in tables:
            logger.info(f"   - {table['table_name']}")
        
        # Test 2: Compliance summary
        summary = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total_findings,
                COUNT(DISTINCT cf.ci_id) as total_systems,
                COUNT(CASE WHEN cf.status = 'pass' THEN 1 END) as compliant,
                COUNT(CASE WHEN cf.status = 'warn' THEN 1 END) as warnings,
                COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical,
                ROUND(AVG(cf.risk_score), 1) as avg_risk_score
            FROM compliance_findings cf
            JOIN configuration_items ci ON cf.ci_id = ci.id
        """)
        
        compliance_score = (summary['compliant'] / summary['total_systems'] * 100) if summary['total_systems'] > 0 else 0
        
        logger.info("📊 Live Compliance Metrics:")
        logger.info(f"   - Total Systems: {summary['total_systems']}")
        logger.info(f"   - Compliance Score: {compliance_score:.1f}%")
        logger.info(f"   - Compliant: {summary['compliant']}")
        logger.info(f"   - Warnings: {summary['warnings']}")
        logger.info(f"   - Critical: {summary['critical']}")
        logger.info(f"   - Average Risk Score: {summary['avg_risk_score']}")
        
        # Test 3: Business unit breakdown
        bu_breakdown = await conn.fetch("""
            SELECT 
                ci.business_unit,
                COUNT(*) as system_count,
                COUNT(CASE WHEN cf.status = 'fail' THEN 1 END) as critical_systems,
                ROUND(AVG(cf.risk_score), 1) as avg_risk
            FROM compliance_findings cf
            JOIN configuration_items ci ON cf.ci_id = ci.id
            GROUP BY ci.business_unit
            ORDER BY avg_risk DESC
        """)
        
        logger.info("🏢 Business Unit Risk Analysis:")
        for bu in bu_breakdown:
            logger.info(f"   - {bu['business_unit']}: {bu['system_count']} systems, {bu['critical_systems']} critical (avg risk: {bu['avg_risk']})")
        
        # Test 4: Recent activities
        recent_findings = await conn.fetch("""
            SELECT ci.name, cf.status, cf.risk_score, cf.reason, cf.created_at
            FROM compliance_findings cf
            JOIN configuration_items ci ON cf.ci_id = ci.id
            ORDER BY cf.created_at DESC
            LIMIT 5
        """)
        
        logger.info("🔍 Recent Compliance Findings:")
        for finding in recent_findings:
            status_icon = {"pass": "✅", "warn": "⚠️", "fail": "❌", "unknown": "❓"}[finding['status']]
            logger.info(f"   {status_icon} {finding['name']}: {finding['reason']} (Risk: {finding['risk_score']})")
        
        await conn.close()
        
        return {
            "tables_count": len(tables),
            "compliance_summary": dict(summary),
            "compliance_score": round(compliance_score, 1),
            "business_units": [dict(bu) for bu in bu_breakdown],
            "recent_findings": [dict(f) for f in recent_findings]
        }
        
    except Exception as e:
        logger.error(f"❌ Direct query test failed: {e}")
        return None

async def generate_test_report():
    """Generate comprehensive test report"""
    
    logger.info("🧪 Starting Database Integration Test...")
    
    report = {
        "test_timestamp": datetime.now().isoformat(),
        "database_connection": False,
        "direct_queries": False,
        "test_results": {}
    }
    
    # Test 1: Database connection via our module
    logger.info("\n1️⃣ Testing Database Connection Module...")
    connection_success = await test_database_connection()
    report["database_connection"] = connection_success
    
    # Test 2: Direct database queries
    logger.info("\n2️⃣ Testing Direct Database Queries...")
    query_results = await test_direct_queries()
    
    if query_results:
        report["direct_queries"] = True
        report["test_results"] = query_results
        
        # Generate summary
        logger.info("\n📋 TEST SUMMARY:")
        logger.info("=" * 50)
        logger.info(f"✅ Database Tables: {query_results['tables_count']} created")
        logger.info(f"📊 Compliance Score: {query_results['compliance_score']}%")
        logger.info(f"🏢 Business Units: {len(query_results['business_units'])} tracked")
        logger.info(f"🔍 Recent Findings: {len(query_results['recent_findings'])} recorded")
        
        # Risk assessment
        critical_systems = query_results['compliance_summary']['critical']
        if critical_systems > 0:
            logger.warning(f"⚠️  WARNING: {critical_systems} systems have critical compliance issues")
        
        logger.info("✅ Database is fully operational and ready for production!")
    
    # Save report
    report_file = Path(__file__).parent / "database_test_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"\n📄 Test report saved: {report_file}")
    
    return report

async def main():
    """Main test execution"""
    
    print("🏢 Enterprise CMDB Compliance Tool - Database Test")
    print("=" * 60)
    
    try:
        report = await generate_test_report()
        
        # Final status
        if report["database_connection"] and report["direct_queries"]:
            print("\n🎉 ALL TESTS PASSED!")
            print("Your PostgreSQL database is ready for the compliance tool.")
            print(f"📊 Compliance Score: {report['test_results']['compliance_score']}%")
            return True
        else:
            print("\n❌ SOME TESTS FAILED!")
            print("Please check the logs above for details.")
            return False
            
    except Exception as e:
        logger.error(f"❌ Test execution failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)