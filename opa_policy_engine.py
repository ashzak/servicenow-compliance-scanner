#!/usr/bin/env python3
"""
OPA (Open Policy Agent) Policy Engine
Policy-as-code compliance evaluation with Rego rules
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from enterprise_architecture import PolicyEngine, CI, OSFacts, LifecycleInfo, ComplianceFinding, ComplianceStatus

logger = logging.getLogger(__name__)

class OPAPolicyEngine(PolicyEngine):
    """Open Policy Agent integration for compliance policy evaluation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.policy_dir = Path(config.get("policy_dir", "./policies"))
        self.opa_binary = config.get("opa_binary", "opa")
        self.decision_log = config.get("decision_log", True)
        self.policies = {}
        
        # Create policy directory if it doesn't exist
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize default policies
        self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default compliance policies"""
        
        # Baseline EOL/EOS policy
        baseline_policy = """
package baseline.compliance

import future.keywords.if

# Default decision
default allow := false
default status := {"level": "pass", "reason": "Compliant", "score": 0}

# Input structure validation
input_valid if {
    input.ci
    input.os_facts
    input.lifecycle
}

# EOL/EOS violation rules
eol_violation if {
    input.lifecycle.is_eol == true
}

eos_violation if {
    input.lifecycle.is_eos == true
}

# Warning thresholds
warn_eol if {
    not eol_violation
    input.lifecycle.days_to_eol <= 180
    input.lifecycle.days_to_eol > 0
}

warn_eos if {
    not eos_violation
    input.lifecycle.days_to_eos <= 365
    input.lifecycle.days_to_eos > 0
}

# Critical vulnerabilities
critical_vulns if {
    input.vulnerabilities.kev_vulnerabilities
    count(input.vulnerabilities.kev_vulnerabilities) > 0
}

# Risk scoring
risk_score := score if {
    score := (eol_multiplier * 40) + 
             (eos_multiplier * 30) + 
             (warn_eol_multiplier * 20) + 
             (warn_eos_multiplier * 10) + 
             (vuln_multiplier * 25)
} else := 0

eol_multiplier := 1 if eol_violation else := 0
eos_multiplier := 1 if eos_violation else := 0
warn_eol_multiplier := 1 if warn_eol else := 0
warn_eos_multiplier := 1 if warn_eos else := 0
vuln_multiplier := count(input.vulnerabilities.kev_vulnerabilities) if critical_vulns else := 0

# Final status determination
status := {"level": "fail", "reason": reason, "score": risk_score} if {
    eol_violation
    reason := sprintf("System is past End-of-Life (%s)", [input.lifecycle.eol_date])
}

status := {"level": "fail", "reason": reason, "score": risk_score} if {
    eos_violation
    reason := sprintf("System is past End-of-Support (%s)", [input.lifecycle.eos_date])
}

status := {"level": "fail", "reason": reason, "score": risk_score} if {
    critical_vulns
    reason := sprintf("System has %d known exploited vulnerabilities", [count(input.vulnerabilities.kev_vulnerabilities)])
}

status := {"level": "warn", "reason": reason, "score": risk_score} if {
    not eol_violation
    not eos_violation
    not critical_vulns
    warn_eol
    reason := sprintf("System approaching End-of-Life in %d days", [input.lifecycle.days_to_eol])
}

status := {"level": "warn", "reason": reason, "score": risk_score} if {
    not eol_violation
    not eos_violation
    not critical_vulns
    not warn_eol
    warn_eos
    reason := sprintf("System approaching End-of-Support in %d days", [input.lifecycle.days_to_eos])
}

# Remediation recommendations
remediation := recommendations if {
    recommendations := [rec |
        some rec in remediation_rules[_]
        rec.condition
    ]
}

remediation_rules := [
    {
        "condition": eol_violation,
        "action": "immediate_upgrade",
        "description": "Upgrade to supported OS version immediately",
        "priority": "P1_CRITICAL",
        "timeline": "Within 24-48 hours"
    },
    {
        "condition": eos_violation,
        "action": "migration_required",
        "description": "Migrate to supported platform",
        "priority": "P1_CRITICAL", 
        "timeline": "Within 1-2 weeks"
    },
    {
        "condition": critical_vulns,
        "action": "security_patches",
        "description": "Apply security patches for known exploited vulnerabilities",
        "priority": "P1_CRITICAL",
        "timeline": "Immediately"
    },
    {
        "condition": warn_eol,
        "action": "plan_upgrade",
        "description": "Plan OS upgrade within maintenance window",
        "priority": "P2_HIGH",
        "timeline": "Within 30-60 days"
    },
    {
        "condition": warn_eos,
        "action": "begin_migration_planning",
        "description": "Begin migration planning for end-of-support",
        "priority": "P3_MEDIUM",
        "timeline": "Within 90 days"
    }
]
"""
        
        # Business unit specific policy
        business_unit_policy = """
package business_unit.compliance

import future.keywords.if

# Healthcare/HIPAA specific rules
healthcare_compliant if {
    input.ci.business_unit == "Healthcare"
    baseline_compliant
    encryption_required
    audit_logging_enabled
}

# Financial/SOX specific rules  
financial_compliant if {
    input.ci.business_unit == "Financial"
    baseline_compliant
    change_control_required
    segregation_of_duties
}

# Manufacturing specific rules
manufacturing_compliant if {
    input.ci.business_unit == "Manufacturing"
    baseline_compliant
    availability_requirements
}

# Base compliance check
baseline_compliant if {
    not input.lifecycle.is_eol
    not input.lifecycle.is_eos
}

# Example requirement checks (would be implemented based on actual data)
encryption_required := true  # Placeholder
audit_logging_enabled := true  # Placeholder
change_control_required := true  # Placeholder
segregation_of_duties := true  # Placeholder
availability_requirements := true  # Placeholder

# Business unit risk multipliers
bu_risk_multiplier := 1.5 if input.ci.business_unit == "Healthcare"
bu_risk_multiplier := 1.3 if input.ci.business_unit == "Financial"
bu_risk_multiplier := 1.0  # Default
"""
        
        # Minimum version policy
        min_version_policy = """
package min_version.compliance

import future.keywords.if

# Minimum version requirements by product
min_versions := {
    "windows-server": "2016",
    "windows": "10",
    "ubuntu": "18.04",
    "rhel": "7",
    "centos": "7",
    "cisco-ios": "15.0",
    "junos": "18.0"
}

# Version comparison helpers
version_parts(version) := parts if {
    parts := split(version, ".")
}

version_number(version) := num if {
    parts := version_parts(version)
    # Simple numeric comparison for major.minor versions
    major := to_number(parts[0])
    minor := to_number(parts[1]) if count(parts) > 1 else := 0
    num := (major * 1000) + minor
}

# Check if current version meets minimum
meets_minimum_version if {
    min_version := min_versions[input.os_facts.product]
    current_num := version_number(input.os_facts.version)
    min_num := version_number(min_version)
    current_num >= min_num
}

# Special cases for complex version schemes
meets_minimum_version if {
    input.os_facts.product == "windows-server"
    to_number(input.os_facts.version) >= 2016
}

violation if {
    input.os_facts.product in object.keys(min_versions)
    not meets_minimum_version
}

status := {"level": "fail", "reason": reason, "score": 30} if {
    violation
    min_version := min_versions[input.os_facts.product]
    reason := sprintf("Version %s below minimum required %s", [input.os_facts.version, min_version])
}

status := {"level": "pass", "reason": "Meets minimum version requirements", "score": 0} if {
    not violation
}
"""
        
        # Write policies to files
        policies = {
            "baseline.rego": baseline_policy,
            "business_unit.rego": business_unit_policy,
            "min_version.rego": min_version_policy
        }
        
        for filename, policy_content in policies.items():
            policy_file = self.policy_dir / filename
            if not policy_file.exists():
                policy_file.write_text(policy_content)
                logger.info(f"Created default policy: {filename}")
    
    async def evaluate(
        self,
        ci: CI,
        os_facts: OSFacts,
        lifecycle: LifecycleInfo,
        policies: List[Dict[str, Any]]
    ) -> ComplianceFinding:
        """Evaluate compliance using OPA policies"""
        
        try:
            # Prepare input document for OPA
            input_doc = self._prepare_input(ci, os_facts, lifecycle)
            
            # Evaluate against each applicable policy
            results = {}
            
            for policy in policies:
                policy_id = policy.get("id", "baseline")
                result = await self._evaluate_policy(input_doc, policy_id)
                results[policy_id] = result
            
            # Combine results into final finding
            return self._create_finding(ci, results, input_doc)
            
        except Exception as e:
            logger.error(f"Policy evaluation failed for {ci.name}: {e}")
            return ComplianceFinding(
                ci_id=ci.id,
                evaluated_at=datetime.now(),
                status=ComplianceStatus.UNKNOWN,
                reason=f"Policy evaluation error: {str(e)}",
                evidence={"error": str(e)},
                policy_id="error"
            )
    
    def _prepare_input(self, ci: CI, os_facts: OSFacts, lifecycle: LifecycleInfo) -> Dict[str, Any]:
        """Prepare input document for OPA evaluation"""
        
        return {
            "ci": {
                "id": ci.id,
                "name": ci.name,
                "class": ci.ci_class,
                "business_unit": ci.business_unit,
                "owner": ci.owner,
                "ip_address": ci.ip_address,
                "tags": ci.tags
            },
            "os_facts": {
                "product": os_facts.product,
                "version": os_facts.version,
                "edition": os_facts.edition,
                "kernel": os_facts.kernel,
                "confidence": os_facts.confidence,
                "connector_used": os_facts.connector_used.value,
                "collected_at": os_facts.collected_at.isoformat()
            },
            "lifecycle": {
                "product": lifecycle.product,
                "version": lifecycle.version,
                "eol_date": lifecycle.eol_date.isoformat() if lifecycle.eol_date else None,
                "eos_date": lifecycle.eos_date.isoformat() if lifecycle.eos_date else None,
                "is_eol": lifecycle.is_eol,
                "is_eos": lifecycle.is_eos,
                "days_to_eol": lifecycle.days_to_eol,
                "days_to_eos": lifecycle.days_to_eol,  # Assuming same calculation
                "lts": lifecycle.lts,
                "latest_version": lifecycle.latest_version,
                "source": lifecycle.source
            },
            "vulnerabilities": {
                "kev_vulnerabilities": [],  # Would be populated by vulnerability enricher
                "high_risk_cves": [],
                "vulnerability_count": 0
            },
            "policies": {
                "evaluation_time": datetime.now().isoformat()
            }
        }
    
    async def _evaluate_policy(self, input_doc: Dict[str, Any], policy_id: str) -> Dict[str, Any]:
        """Evaluate input against a specific policy using OPA"""
        
        try:
            # Write input to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(input_doc, temp_file)
                input_file = temp_file.name
            
            # Determine policy package based on policy_id
            package_map = {
                "baseline": "baseline.compliance",
                "business_unit": "business_unit.compliance", 
                "min_version": "min_version.compliance"
            }
            
            package = package_map.get(policy_id, "baseline.compliance")
            
            # Run OPA evaluation
            cmd = [
                self.opa_binary, "eval",
                "--data", str(self.policy_dir),
                "--input", input_file,
                "--format", "json",
                f"data.{package}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Clean up temp file
            Path(input_file).unlink()
            
            if process.returncode == 0:
                result = json.loads(stdout.decode())
                return result.get("result", [{}])[0] if result.get("result") else {}
            else:
                error_msg = stderr.decode() if stderr else "Unknown OPA error"
                logger.error(f"OPA evaluation failed: {error_msg}")
                return {"error": error_msg}
                
        except FileNotFoundError:
            logger.error(f"OPA binary not found: {self.opa_binary}")
            return {"error": "OPA binary not available"}
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return {"error": str(e)}
    
    def _create_finding(
        self, 
        ci: CI, 
        policy_results: Dict[str, Any],
        input_doc: Dict[str, Any]
    ) -> ComplianceFinding:
        """Create compliance finding from policy evaluation results"""
        
        # Determine overall status (worst case)
        overall_status = ComplianceStatus.PASS
        overall_reason = "Compliant with all policies"
        overall_score = 0
        remediation_actions = []
        evidence = {}
        
        for policy_id, result in policy_results.items():
            if "error" in result:
                overall_status = ComplianceStatus.UNKNOWN
                overall_reason = f"Policy evaluation error: {result['error']}"
                evidence[f"{policy_id}_error"] = result["error"]
                continue
            
            # Extract policy decision
            status_info = result.get("status", {})
            if isinstance(status_info, dict):
                level = status_info.get("level", "pass")
                reason = status_info.get("reason", "")
                score = status_info.get("score", 0)
                
                # Update overall status (fail > warn > pass)
                if level == "fail" and overall_status != ComplianceStatus.FAIL:
                    overall_status = ComplianceStatus.FAIL
                    overall_reason = reason
                elif level == "warn" and overall_status == ComplianceStatus.PASS:
                    overall_status = ComplianceStatus.WARN
                    overall_reason = reason
                
                # Accumulate risk score
                overall_score = max(overall_score, score)
                
                # Collect remediation actions
                remediation = result.get("remediation", [])
                if remediation:
                    remediation_actions.extend(remediation)
                
                # Store evidence
                evidence[f"{policy_id}_result"] = status_info
        
        # Generate final remediation text
        final_remediation = self._generate_remediation_text(remediation_actions)
        
        return ComplianceFinding(
            ci_id=ci.id,
            evaluated_at=datetime.now(),
            status=overall_status,
            reason=overall_reason,
            evidence=evidence,
            policy_id="combined",
            risk_score=min(overall_score, 100),  # Cap at 100
            remediation=final_remediation
        )
    
    def _generate_remediation_text(self, remediation_actions: List[Dict[str, Any]]) -> str:
        """Generate remediation text from policy actions"""
        
        if not remediation_actions:
            return "No remediation required - system is compliant"
        
        # Sort by priority
        priority_order = {"P1_CRITICAL": 1, "P2_HIGH": 2, "P3_MEDIUM": 3, "P4_LOW": 4}
        
        sorted_actions = sorted(
            remediation_actions,
            key=lambda x: priority_order.get(x.get("priority", "P4_LOW"), 5)
        )
        
        remediation_text = "Remediation Required:\n"
        
        for i, action in enumerate(sorted_actions[:5], 1):  # Limit to top 5
            priority = action.get("priority", "")
            description = action.get("description", "")
            timeline = action.get("timeline", "")
            
            remediation_text += f"{i}. [{priority}] {description}"
            if timeline:
                remediation_text += f" (Timeline: {timeline})"
            remediation_text += "\n"
        
        if len(remediation_actions) > 5:
            remediation_text += f"... and {len(remediation_actions) - 5} more actions\n"
        
        return remediation_text.strip()
    
    async def load_custom_policies(self, policy_files: List[str]) -> None:
        """Load custom policy files"""
        
        for policy_file in policy_files:
            try:
                policy_path = Path(policy_file)
                if policy_path.exists():
                    # Copy to policy directory
                    dest_path = self.policy_dir / policy_path.name
                    dest_path.write_text(policy_path.read_text())
                    logger.info(f"Loaded custom policy: {policy_path.name}")
                else:
                    logger.warning(f"Policy file not found: {policy_file}")
            except Exception as e:
                logger.error(f"Failed to load policy {policy_file}: {e}")
    
    async def validate_policies(self) -> Dict[str, Any]:
        """Validate all policies using OPA"""
        
        validation_results = {}
        
        for policy_file in self.policy_dir.glob("*.rego"):
            try:
                cmd = [
                    self.opa_binary, "fmt",
                    "--diff",
                    str(policy_file)
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                validation_results[policy_file.name] = {
                    "valid": process.returncode == 0,
                    "errors": stderr.decode() if stderr else None
                }
                
            except Exception as e:
                validation_results[policy_file.name] = {
                    "valid": False,
                    "errors": str(e)
                }
        
        return validation_results
    
    async def get_policy_documentation(self) -> Dict[str, Any]:
        """Generate documentation for all policies"""
        
        documentation = {}
        
        for policy_file in self.policy_dir.glob("*.rego"):
            try:
                content = policy_file.read_text()
                
                # Extract comments and rules
                rules = []
                comments = []
                
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('#'):
                        comments.append(line[1:].strip())
                    elif ' if {' in line or ' := ' in line:
                        rules.append(line)
                
                documentation[policy_file.name] = {
                    "description": comments[:5],  # First 5 comment lines
                    "rules_count": len(rules),
                    "file_size": policy_file.stat().st_size,
                    "last_modified": datetime.fromtimestamp(
                        policy_file.stat().st_mtime
                    ).isoformat()
                }
                
            except Exception as e:
                documentation[policy_file.name] = {
                    "error": str(e)
                }
        
        return documentation

class PolicyManager:
    """Manages policy lifecycle and testing"""
    
    def __init__(self, policy_engine: OPAPolicyEngine):
        self.policy_engine = policy_engine
        self.test_cases = []
    
    async def create_policy_from_template(
        self, 
        template_name: str, 
        parameters: Dict[str, Any]
    ) -> str:
        """Create policy from template with parameters"""
        
        templates = {
            "minimum_version": """
package custom.min_version_{product}

min_version := "{min_version}"

violation if {{
    input.os_facts.product == "{product}"
    version_number(input.os_facts.version) < version_number(min_version)
}}

version_number(version) := num if {{
    to_number(version)
}}

status := {{"level": "fail", "reason": reason, "score": 25}} if {{
    violation
    reason := sprintf("Version %s below minimum %s", [input.os_facts.version, min_version])
}}

status := {{"level": "pass", "reason": "Meets minimum version", "score": 0}} if {{
    not violation
}}
""",
            
            "business_unit_restriction": """
package custom.bu_{business_unit}

allowed_products := {allowed_products}

violation if {{
    input.ci.business_unit == "{business_unit}"
    not input.os_facts.product in allowed_products
}}

status := {{"level": "fail", "reason": reason, "score": 20}} if {{
    violation
    reason := sprintf("Product %s not allowed in %s", [input.os_facts.product, "{business_unit}"])
}}

status := {{"level": "pass", "reason": "Product approved for business unit", "score": 0}} if {{
    not violation
}}
"""
        }
        
        template = templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")
        
        # Format template with parameters
        policy_content = template.format(**parameters)
        
        # Generate filename
        policy_name = f"custom_{template_name}_{hash(str(parameters)) % 10000}.rego"
        policy_file = self.policy_engine.policy_dir / policy_name
        
        # Write policy
        policy_file.write_text(policy_content)
        
        logger.info(f"Created custom policy: {policy_name}")
        return policy_name
    
    async def test_policy(
        self, 
        policy_name: str, 
        test_cases: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Test policy against provided test cases"""
        
        results = []
        
        for i, test_case in enumerate(test_cases):
            input_doc = test_case.get("input")
            expected = test_case.get("expected")
            
            try:
                # Extract package name from policy file
                policy_file = self.policy_engine.policy_dir / policy_name
                content = policy_file.read_text()
                
                # Simple package extraction
                package_match = re.search(r'package\s+([\w.]+)', content)
                if package_match:
                    package = package_match.group(1)
                else:
                    package = "test"
                
                # Evaluate
                result = await self.policy_engine._evaluate_policy(input_doc, package)
                
                # Compare with expected
                passed = self._compare_results(result, expected)
                
                results.append({
                    "test_case": i + 1,
                    "passed": passed,
                    "result": result,
                    "expected": expected
                })
                
            except Exception as e:
                results.append({
                    "test_case": i + 1,
                    "passed": False,
                    "error": str(e)
                })
        
        return {
            "policy": policy_name,
            "total_tests": len(test_cases),
            "passed_tests": len([r for r in results if r.get("passed", False)]),
            "results": results
        }
    
    def _compare_results(self, actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        """Compare actual result with expected result"""
        
        if not expected:
            return True  # No expectations
        
        for key, expected_value in expected.items():
            if key not in actual:
                return False
            
            if isinstance(expected_value, dict):
                if not self._compare_results(actual[key], expected_value):
                    return False
            else:
                if actual[key] != expected_value:
                    return False
        
        return True

# Example usage
async def demo_opa_policy_engine():
    """Demonstrate OPA policy engine"""
    
    config = {
        "policy_dir": "./demo_policies",
        "opa_binary": "opa",
        "decision_log": True
    }
    
    # Create policy engine
    engine = OPAPolicyEngine(config)
    
    # Validate policies
    validation = await engine.validate_policies()
    print("Policy Validation:")
    for policy, result in validation.items():
        status = "✓" if result["valid"] else "✗"
        print(f"  {status} {policy}")
        if result.get("errors"):
            print(f"    Errors: {result['errors']}")
    
    # Create test data
    from enterprise_architecture import CI, OSFacts, LifecycleInfo, ConnectorType
    
    test_ci = CI(
        id="test-001",
        sn_sys_id="test-001", 
        name="legacy-server",
        ci_class="cmdb_ci_win_server",
        business_unit="Healthcare",
        ip_address="10.1.1.100"
    )
    
    test_os_facts = OSFacts(
        ci_id="test-001",
        collected_at=datetime.now(),
        product="windows-server",
        version="2008",
        connector_used=ConnectorType.WINRM,
        raw_data={}
    )
    
    test_lifecycle = LifecycleInfo(
        product="windows-server",
        version="2008",
        eol_date=datetime(2020, 1, 14),  # Past EOL
        eos_date=datetime(2023, 1, 10),
        lts=False,
        source="endoflife.date"
    )
    
    # Evaluate compliance
    policies = [{"id": "baseline"}, {"id": "min_version"}]
    
    finding = await engine.evaluate(test_ci, test_os_facts, test_lifecycle, policies)
    
    print(f"\nCompliance Evaluation:")
    print(f"  Status: {finding.status.value}")
    print(f"  Reason: {finding.reason}")
    print(f"  Risk Score: {finding.risk_score}")
    print(f"  Remediation: {finding.remediation}")

if __name__ == "__main__":
    asyncio.run(demo_opa_policy_engine())