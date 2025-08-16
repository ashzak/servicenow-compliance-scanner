#!/usr/bin/env python3
"""
Simplified Enterprise CMDB Compliance Tool Demo
Demonstrates core concepts without external dependencies
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List
from enum import Enum

class ComplianceStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail" 
    UNKNOWN = "unknown"

class CI:
    """Simple Configuration Item"""
    def __init__(self, id: str, name: str, ci_class: str, business_unit: str, ip_address: str):
        self.id = id
        self.name = name
        self.ci_class = ci_class
        self.business_unit = business_unit
        self.ip_address = ip_address

class OSFacts:
    """OS Information"""
    def __init__(self, ci_id: str, product: str, version: str, confidence: float):
        self.ci_id = ci_id
        self.product = product
        self.version = version
        self.confidence = confidence
        self.collected_at = datetime.now()

class LifecycleInfo:
    """Lifecycle Information"""
    def __init__(self, product: str, version: str, eol_date: datetime, eos_date: datetime):
        self.product = product
        self.version = version
        self.eol_date = eol_date
        self.eos_date = eos_date
    
    @property
    def is_eol(self) -> bool:
        return datetime.now() > self.eol_date
    
    @property
    def is_eos(self) -> bool:
        return datetime.now() > self.eos_date
    
    @property
    def days_to_eol(self) -> int:
        return (self.eol_date - datetime.now()).days

class ComplianceFinding:
    """Compliance Finding"""
    def __init__(self, ci_id: str, status: ComplianceStatus, reason: str, risk_score: int):
        self.ci_id = ci_id
        self.status = status
        self.reason = reason
        self.risk_score = risk_score
        self.evaluated_at = datetime.now()

class EnterpriseComplianceDemo:
    """Simplified enterprise compliance demonstration"""
    
    def __init__(self):
        self.demo_data = self._create_demo_data()
    
    def _create_demo_data(self):
        """Create comprehensive demo dataset"""
        
        # Sample CIs
        demo_cis = [
            CI("ci_001", "legacy-dc-01", "cmdb_ci_win_server", "Finance", "10.1.1.10"),
            CI("ci_002", "web-app-02", "cmdb_ci_unix_server", "Marketing", "10.1.2.20"), 
            CI("ci_003", "app-server-03", "cmdb_ci_win_server", "Engineering", "10.1.3.30"),
            CI("ci_004", "core-switch-01", "cmdb_ci_switch", "IT Operations", "10.1.0.1"),
            CI("ci_005", "mystery-server-05", "cmdb_ci_computer", "Research", "10.1.5.50")
        ]
        
        # OS Facts
        demo_os_facts = [
            OSFacts("ci_001", "windows-server", "2008-r2", 0.95),
            OSFacts("ci_002", "ubuntu", "18.04", 0.98),
            OSFacts("ci_003", "windows-server", "2022", 0.99),
            OSFacts("ci_004", "cisco-ios", "12.4", 0.90),
            OSFacts("ci_005", "", "", 0.2)
        ]
        
        # Lifecycle Information
        demo_lifecycle = [
            LifecycleInfo("windows-server", "2008-r2", 
                         datetime(2020, 1, 14), datetime(2023, 1, 10)),
            LifecycleInfo("ubuntu", "18.04",
                         datetime(2023, 5, 31), datetime(2028, 5, 31)),
            LifecycleInfo("windows-server", "2022",
                         datetime(2031, 10, 14), datetime(2033, 10, 14)),
            LifecycleInfo("cisco-ios", "12.4",
                         datetime(2016, 7, 31), datetime(2019, 7, 31)),
            None
        ]
        
        return {
            "cis": demo_cis,
            "os_facts": demo_os_facts,
            "lifecycle": demo_lifecycle
        }
    
    async def run_demo(self):
        """Run complete enterprise compliance demonstration"""
        
        print("🏢 Enterprise CMDB Compliance Tool - Demo")
        print("=" * 50)
        print()
        
        await self._demo_architecture()
        await self._demo_scanning_workflow()
        await self._demo_compliance_evaluation()
        await self._demo_enterprise_features()
        
        print("\n🎉 Demo completed!")
    
    async def _demo_architecture(self):
        """Show architecture overview"""
        
        print("🏗️  ENTERPRISE ARCHITECTURE")
        print("-" * 30)
        print("""
Enterprise CMDB Compliance Tool Components:

┌─────────────────┬─────────────────┬─────────────────┐
│   Data Layer    │  Processing     │   Interfaces    │
├─────────────────┼─────────────────┼─────────────────┤
│ • ServiceNow    │ • Scanner       │ • FastAPI REST  │
│   CMDB API      │   Workers       │ • React Web UI  │
│ • endoflife.date│ • OPA Policies  │ • GraphQL API   │
│ • CISA KEV      │ • LLM Assistant │ • CLI Tools     │
│ • PostgreSQL    │ • Normalizer    │ • Webhooks      │
└─────────────────┴─────────────────┴─────────────────┘

Key Capabilities:
✅ Agentless device scanning (SSH/WinRM/NAPALM/SNMP)
✅ Real-time lifecycle data integration
✅ Policy-as-code compliance rules with OPA
✅ AI-powered compliance assistant
✅ Enterprise security with Vault integration
✅ Full observability with OpenTelemetry
        """)
        print()
    
    async def _demo_scanning_workflow(self):
        """Demonstrate scanning workflow"""
        
        print("🔍 SCANNING WORKFLOW DEMONSTRATION")
        print("-" * 40)
        
        print("Connector Technologies:")
        connectors = {
            "SSH/Paramiko": "Linux/Unix servers via SSH",
            "WinRM/pywinrm": "Windows servers via PowerShell",
            "NAPALM": "Network devices (Cisco, Juniper, Arista)",
            "SNMP/PySNMP": "SNMP-enabled devices",
            "Nmap": "Fallback OS detection"
        }
        
        for connector, description in connectors.items():
            print(f"  • {connector}: {description}")
        
        print("\nDemo Scanning Results:")
        for ci, os_facts in zip(self.demo_data["cis"], self.demo_data["os_facts"]):
            confidence_bar = "█" * int(os_facts.confidence * 10)
            print(f"  {ci.name:15} | {os_facts.product:12} {os_facts.version:8} | {confidence_bar} {os_facts.confidence:.0%}")
        
        print()
    
    async def _demo_compliance_evaluation(self):
        """Demonstrate compliance evaluation"""
        
        print("⚖️  COMPLIANCE EVALUATION")
        print("-" * 30)
        
        print("Policy Engine (OPA/Rego) Rules:")
        print("  • End-of-Life (EOL) detection")
        print("  • End-of-Support (EOS) warnings")
        print("  • Minimum version requirements")
        print("  • Business unit specific policies")
        print("  • Critical vulnerability flags")
        print()
        
        findings = []
        
        print("Compliance Assessment Results:")
        print("System               Status      Risk   Reason")
        print("-" * 55)
        
        for ci, os_facts, lifecycle in zip(
            self.demo_data["cis"],
            self.demo_data["os_facts"], 
            self.demo_data["lifecycle"]
        ):
            if lifecycle and os_facts.product:
                # Evaluate compliance
                status = ComplianceStatus.PASS
                risk_score = 0
                reason = "Compliant"
                
                if lifecycle.is_eol:
                    status = ComplianceStatus.FAIL
                    risk_score = 90
                    reason = f"Past EOL ({lifecycle.eol_date.strftime('%Y-%m-%d')})"
                elif lifecycle.is_eos:
                    status = ComplianceStatus.FAIL
                    risk_score = 80
                    reason = f"Past EOS ({lifecycle.eos_date.strftime('%Y-%m-%d')})"
                elif lifecycle.days_to_eol <= 180 and lifecycle.days_to_eol > 0:
                    status = ComplianceStatus.WARN
                    risk_score = 60
                    reason = f"EOL in {lifecycle.days_to_eol} days"
                
                finding = ComplianceFinding(ci.id, status, reason, risk_score)
                findings.append(finding)
                
                # Status icon
                icon = {"pass": "✅", "warn": "⚠️", "fail": "❌"}[status.value]
                
                print(f"{ci.name:18} {icon} {status.value:8} {risk_score:3d}   {reason}")
            else:
                finding = ComplianceFinding(ci.id, ComplianceStatus.UNKNOWN, "No data", 0)
                findings.append(finding)
                print(f"{ci.name:18} ❓ unknown    0   No lifecycle data")
        
        # Summary
        print("\n📊 COMPLIANCE SUMMARY")
        print("-" * 25)
        
        total = len(findings)
        compliant = len([f for f in findings if f.status == ComplianceStatus.PASS])
        at_risk = len([f for f in findings if f.status == ComplianceStatus.WARN])
        non_compliant = len([f for f in findings if f.status == ComplianceStatus.FAIL])
        unknown = len([f for f in findings if f.status == ComplianceStatus.UNKNOWN])
        
        print(f"Total Systems: {total}")
        print(f"✅ Compliant: {compliant}")
        print(f"⚠️  At Risk: {at_risk}")
        print(f"❌ Non-Compliant: {non_compliant}")
        print(f"❓ Unknown: {unknown}")
        
        compliance_score = (compliant / total) * 100 if total > 0 else 0
        print(f"📈 Compliance Score: {compliance_score:.1f}%")
        print()
    
    async def _demo_enterprise_features(self):
        """Show enterprise capabilities"""
        
        print("🏢 ENTERPRISE FEATURES")
        print("-" * 25)
        
        features = {
            "Security & Compliance": [
                "HashiCorp Vault for secrets management",
                "mTLS encryption for all communications", 
                "RBAC with LDAP/AD integration",
                "Audit logging and compliance trails",
                "SOC 2 Type II compliance ready"
            ],
            "Scalability & Performance": [
                "Async/await architecture throughout",
                "Horizontal scaling with Kubernetes",
                "Redis caching and session management",
                "Circuit breaker patterns for resilience",
                "Connection pooling and rate limiting"
            ],
            "AI & Automation": [
                "vLLM + Llama 3.x compliance assistant",
                "RAG over compliance policies and findings",
                "Natural language query interface",
                "Automated remediation recommendations",
                "Tool calling for data retrieval"
            ],
            "Integration & Workflow": [
                "ServiceNow bidirectional integration",
                "Automatic change request generation",
                "Slack/Teams notification integration",
                "Custom workflow orchestration",
                "RESTful API with GraphQL support"
            ],
            "Observability": [
                "OpenTelemetry instrumentation",
                "Prometheus metrics collection",
                "Jaeger distributed tracing",
                "Grafana dashboards",
                "Custom alerting rules"
            ]
        }
        
        for category, feature_list in features.items():
            print(f"\n{category}:")
            for feature in feature_list:
                print(f"  • {feature}")
        
        print()

async def main():
    """Main demo execution"""
    
    demo = EnterpriseComplianceDemo()
    
    try:
        await demo.run_demo()
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted")
    except Exception as e:
        print(f"❌ Demo failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())