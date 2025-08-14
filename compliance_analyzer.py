#!/usr/bin/env python3
"""
OS Compliance and Vulnerability Analysis Module
"""

import requests
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import csv
import os

class ComplianceAnalyzer:
    """OS compliance and end-of-life analysis"""
    
    def __init__(self):
        self.eol_data = {}
        self.vulnerability_db = {}
        self.compliance_rules = {}
        self.load_compliance_databases()
    
    def load_compliance_databases(self):
        """Load EOL and compliance databases"""
        
        print("📊 Loading compliance databases...")
        
        # Load built-in EOL data
        self.eol_data = {
            'windows': {
                'Windows Server 2008': {'eol_date': '2020-01-14', 'eos_date': '2023-01-10'},
                'Windows Server 2008 R2': {'eol_date': '2020-01-14', 'eos_date': '2023-01-10'}, 
                'Windows Server 2012': {'eol_date': '2023-10-10', 'eos_date': '2026-10-10'},
                'Windows Server 2012 R2': {'eol_date': '2023-10-10', 'eos_date': '2026-10-10'},
                'Windows Server 2016': {'eol_date': '2027-01-12', 'eos_date': '2029-01-12'},
                'Windows Server 2019': {'eol_date': '2029-01-09', 'eos_date': '2031-01-09'},
                'Windows Server 2022': {'eol_date': '2031-10-14', 'eos_date': '2033-10-14'},
                'Windows 7': {'eol_date': '2020-01-14', 'eos_date': '2023-01-10'},
                'Windows 8': {'eol_date': '2023-01-10', 'eos_date': '2024-01-10'},
                'Windows 8.1': {'eol_date': '2023-01-10', 'eos_date': '2024-01-10'},
                'Windows 10': {'eol_date': '2025-10-14', 'eos_date': '2027-10-14'},
                'Windows 11': {'eol_date': '2031-10-14', 'eos_date': '2033-10-14'}
            },
            'linux': {
                'Ubuntu 14.04': {'eol_date': '2019-04-25', 'eos_date': '2024-04-25'},
                'Ubuntu 16.04': {'eol_date': '2021-04-30', 'eos_date': '2026-04-30'},
                'Ubuntu 18.04': {'eol_date': '2023-05-31', 'eos_date': '2028-05-31'},
                'Ubuntu 20.04': {'eol_date': '2025-04-23', 'eos_date': '2030-04-23'},
                'Ubuntu 22.04': {'eol_date': '2027-04-21', 'eos_date': '2032-04-21'},
                'CentOS 6': {'eol_date': '2020-11-30', 'eos_date': '2020-11-30'},
                'CentOS 7': {'eol_date': '2024-06-30', 'eos_date': '2024-06-30'},
                'CentOS 8': {'eol_date': '2021-12-31', 'eos_date': '2021-12-31'},
                'RHEL 6': {'eol_date': '2020-11-30', 'eos_date': '2024-06-30'},
                'RHEL 7': {'eol_date': '2024-06-30', 'eos_date': '2026-06-30'},
                'RHEL 8': {'eol_date': '2029-05-31', 'eos_date': '2032-05-31'},
                'RHEL 9': {'eol_date': '2032-05-31', 'eos_date': '2035-05-31'},
                'SLES 11': {'eol_date': '2019-03-31', 'eos_date': '2022-03-31'},
                'SLES 12': {'eol_date': '2024-10-31', 'eos_date': '2027-10-31'},
                'SLES 15': {'eol_date': '2028-07-31', 'eos_date': '2031-07-31'}
            },
            'network': {
                'Cisco IOS 12.4': {'eol_date': '2016-07-31', 'eos_date': '2019-07-31'},
                'Cisco IOS 15.0': {'eol_date': '2018-08-01', 'eos_date': '2021-08-01'},
                'Cisco IOS 15.1': {'eol_date': '2020-10-31', 'eos_date': '2023-10-31'},
                'Cisco IOS-XE 16.9': {'eol_date': '2024-07-31', 'eos_date': '2027-07-31'},
                'Cisco IOS-XE 17.3': {'eol_date': '2026-10-31', 'eos_date': '2029-10-31'},
                'Junos 12.3': {'eol_date': '2018-06-30', 'eos_date': '2021-06-30'},
                'Junos 15.1': {'eol_date': '2020-12-31', 'eos_date': '2023-12-31'},
                'Junos 18.4': {'eol_date': '2023-12-31', 'eos_date': '2026-12-31'},
                'Junos 20.4': {'eol_date': '2025-12-31', 'eos_date': '2028-12-31'}
            }
        }
        
        # Load compliance rules
        self.compliance_rules = {
            'critical_eol': {
                'description': 'Systems past End-of-Life date',
                'severity': 'CRITICAL',
                'sla_days': 0  # Immediate action required
            },
            'approaching_eol': {
                'description': 'Systems approaching End-of-Life (within 6 months)',
                'severity': 'HIGH', 
                'sla_days': 30
            },
            'critical_eos': {
                'description': 'Systems past End-of-Support date',
                'severity': 'CRITICAL',
                'sla_days': 0
            },
            'approaching_eos': {
                'description': 'Systems approaching End-of-Support (within 1 year)',
                'severity': 'MEDIUM',
                'sla_days': 90
            },
            'missing_patches': {
                'description': 'Systems missing critical security patches',
                'severity': 'HIGH',
                'sla_days': 7
            },
            'unsupported_version': {
                'description': 'Systems running unsupported OS versions',
                'severity': 'HIGH',
                'sla_days': 30
            }
        }
        
        print("✅ Compliance databases loaded")
    
    def analyze_ci_compliance(self, ci_data: Dict) -> Dict:
        """Analyze compliance for a single CI"""
        
        os_name = ci_data.get('detected_os', ci_data.get('cmdb_os', '')).strip()
        os_version = ci_data.get('detected_version', ci_data.get('cmdb_version', '')).strip()
        ci_name = ci_data.get('ci_name', ci_data.get('name', ''))
        
        analysis = {
            'ci_name': ci_name,
            'ip_address': ci_data.get('ip_address', ''),
            'os_name': os_name,
            'os_version': os_version,
            'analysis_timestamp': datetime.now().isoformat(),
            'compliance_status': 'UNKNOWN',
            'risk_score': 0,
            'violations': [],
            'recommendations': [],
            'eol_info': {},
            'vulnerability_exposure': {},
            'business_impact': 'UNKNOWN'
        }
        
        if not os_name:
            analysis['violations'].append({
                'type': 'missing_os_info',
                'severity': 'MEDIUM',
                'description': 'OS information not available for compliance assessment',
                'recommendation': 'Update CMDB with OS information or perform network discovery'
            })
            return analysis
        
        # Find matching EOL data
        eol_info = self._find_eol_info(os_name, os_version)
        analysis['eol_info'] = eol_info
        
        # Analyze EOL/EOS status
        eol_violations = self._analyze_eol_status(eol_info)
        analysis['violations'].extend(eol_violations)
        
        # Check for known vulnerabilities
        vuln_info = self._check_vulnerabilities(os_name, os_version)
        analysis['vulnerability_exposure'] = vuln_info
        
        # Add vulnerability violations
        if vuln_info.get('critical_vulns', 0) > 0:
            analysis['violations'].append({
                'type': 'critical_vulnerabilities',
                'severity': 'CRITICAL',
                'description': f"{vuln_info['critical_vulns']} critical vulnerabilities found",
                'recommendation': 'Apply security patches immediately'
            })
        
        # Calculate overall risk score
        analysis['risk_score'] = self._calculate_risk_score(analysis)
        
        # Determine compliance status
        analysis['compliance_status'] = self._determine_compliance_status(analysis)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        # Assess business impact
        analysis['business_impact'] = self._assess_business_impact(ci_data, analysis)
        
        return analysis
    
    def _find_eol_info(self, os_name: str, os_version: str) -> Dict:
        """Find EOL information for OS"""
        
        os_lower = os_name.lower()
        
        # Determine OS category
        if 'windows' in os_lower:
            category = 'windows'
        elif any(linux_dist in os_lower for linux_dist in ['ubuntu', 'centos', 'rhel', 'suse', 'sles', 'linux']):
            category = 'linux'
        elif any(network_os in os_lower for network_os in ['cisco', 'ios', 'junos', 'nx-os']):
            category = 'network'
        else:
            return {'status': 'unknown', 'reason': f'Unknown OS category: {os_name}'}
        
        # Search for exact matches
        eol_db = self.eol_data.get(category, {})
        
        # Try direct match first
        full_os_name = f"{os_name} {os_version}".strip()
        for eol_key, eol_data in eol_db.items():
            if eol_key.lower() in full_os_name.lower() or full_os_name.lower() in eol_key.lower():
                return {
                    'status': 'found',
                    'os_match': eol_key,
                    'eol_date': eol_data['eol_date'],
                    'eos_date': eol_data['eos_date'],
                    'days_to_eol': self._days_until_date(eol_data['eol_date']),
                    'days_to_eos': self._days_until_date(eol_data['eos_date'])
                }
        
        # Try partial matches
        for eol_key, eol_data in eol_db.items():
            if any(part in eol_key.lower() for part in os_name.lower().split()):
                return {
                    'status': 'partial_match',
                    'os_match': eol_key,
                    'eol_date': eol_data['eol_date'],
                    'eos_date': eol_data['eos_date'],
                    'days_to_eol': self._days_until_date(eol_data['eol_date']),
                    'days_to_eos': self._days_until_date(eol_data['eos_date']),
                    'confidence': 'low'
                }
        
        return {'status': 'not_found', 'reason': f'No EOL data found for {os_name}'}
    
    def _days_until_date(self, date_str: str) -> int:
        """Calculate days until a date (negative if past)"""
        try:
            target_date = datetime.strptime(date_str, '%Y-%m-%d')
            today = datetime.now()
            return (target_date - today).days
        except:
            return 999999  # Invalid date
    
    def _analyze_eol_status(self, eol_info: Dict) -> List[Dict]:
        """Analyze EOL/EOS status and generate violations"""
        
        violations = []
        
        if eol_info.get('status') != 'found':
            return violations
        
        days_to_eol = eol_info.get('days_to_eol', 999999)
        days_to_eos = eol_info.get('days_to_eos', 999999)
        
        # Check End-of-Life status
        if days_to_eol <= 0:
            violations.append({
                'type': 'critical_eol',
                'severity': 'CRITICAL',
                'description': f"OS is past End-of-Life date ({eol_info['eol_date']})",
                'recommendation': 'Upgrade to supported OS version immediately',
                'days_overdue': abs(days_to_eol)
            })
        elif days_to_eol <= 180:  # Within 6 months
            violations.append({
                'type': 'approaching_eol',
                'severity': 'HIGH',
                'description': f"OS approaching End-of-Life in {days_to_eol} days ({eol_info['eol_date']})",
                'recommendation': 'Plan OS upgrade within maintenance window',
                'days_remaining': days_to_eol
            })
        
        # Check End-of-Support status  
        if days_to_eos <= 0:
            violations.append({
                'type': 'critical_eos',
                'severity': 'CRITICAL',
                'description': f"OS is past End-of-Support date ({eol_info['eos_date']})",
                'recommendation': 'Migrate to supported platform immediately',
                'days_overdue': abs(days_to_eos)
            })
        elif days_to_eos <= 365:  # Within 1 year
            violations.append({
                'type': 'approaching_eos',
                'severity': 'MEDIUM',
                'description': f"OS approaching End-of-Support in {days_to_eos} days ({eol_info['eos_date']})",
                'recommendation': 'Begin migration planning',
                'days_remaining': days_to_eos
            })
        
        return violations
    
    def _check_vulnerabilities(self, os_name: str, os_version: str) -> Dict:
        """Check for known vulnerabilities (simplified)"""
        
        # This would typically query CVE databases, vendor advisories, etc.
        # For demo purposes, we'll simulate vulnerability data
        
        vuln_info = {
            'critical_vulns': 0,
            'high_vulns': 0,
            'medium_vulns': 0,
            'low_vulns': 0,
            'last_check': datetime.now().isoformat(),
            'sources': ['simulated_data']
        }
        
        os_lower = os_name.lower()
        
        # Simulate vulnerability exposure based on OS age and type
        if 'windows' in os_lower:
            if '2008' in os_name or '2012' in os_name:
                vuln_info['critical_vulns'] = 5
                vuln_info['high_vulns'] = 12
            elif '2016' in os_name:
                vuln_info['high_vulns'] = 3
                vuln_info['medium_vulns'] = 8
        elif 'centos' in os_lower and ('6' in os_version or '7' in os_version):
            vuln_info['critical_vulns'] = 3
            vuln_info['high_vulns'] = 7
        elif 'ubuntu' in os_lower and ('14.04' in os_version or '16.04' in os_version):
            vuln_info['critical_vulns'] = 2
            vuln_info['high_vulns'] = 5
        
        return vuln_info
    
    def _calculate_risk_score(self, analysis: Dict) -> int:
        """Calculate overall risk score (0-100)"""
        
        risk_score = 0
        
        # Base score from violations
        for violation in analysis.get('violations', []):
            severity = violation.get('severity', 'LOW')
            if severity == 'CRITICAL':
                risk_score += 30
            elif severity == 'HIGH':
                risk_score += 20
            elif severity == 'MEDIUM':
                risk_score += 10
            elif severity == 'LOW':
                risk_score += 5
        
        # Additional scoring from vulnerability exposure
        vuln_info = analysis.get('vulnerability_exposure', {})
        risk_score += vuln_info.get('critical_vulns', 0) * 15
        risk_score += vuln_info.get('high_vulns', 0) * 5
        risk_score += vuln_info.get('medium_vulns', 0) * 2
        
        # Cap at 100
        return min(risk_score, 100)
    
    def _determine_compliance_status(self, analysis: Dict) -> str:
        """Determine overall compliance status"""
        
        risk_score = analysis.get('risk_score', 0)
        critical_violations = len([v for v in analysis.get('violations', []) if v.get('severity') == 'CRITICAL'])
        
        if critical_violations > 0 or risk_score >= 70:
            return 'NON_COMPLIANT'
        elif risk_score >= 40:
            return 'AT_RISK'
        elif risk_score >= 20:
            return 'MONITORING_REQUIRED'
        else:
            return 'COMPLIANT'
    
    def _generate_recommendations(self, analysis: Dict) -> List[Dict]:
        """Generate prioritized recommendations"""
        
        recommendations = []
        violations = analysis.get('violations', [])
        
        # Priority 1: Critical violations
        critical_violations = [v for v in violations if v.get('severity') == 'CRITICAL']
        if critical_violations:
            recommendations.append({
                'priority': 'P1_CRITICAL',
                'action': 'Immediate remediation required',
                'description': 'Address critical EOL/EOS and security vulnerabilities',
                'timeline': 'Within 24-48 hours',
                'violations_addressed': len(critical_violations)
            })
        
        # Priority 2: High violations  
        high_violations = [v for v in violations if v.get('severity') == 'HIGH']
        if high_violations:
            recommendations.append({
                'priority': 'P2_HIGH',
                'action': 'Plan urgent maintenance',
                'description': 'Schedule maintenance window for upgrades and patches',
                'timeline': 'Within 1-2 weeks',
                'violations_addressed': len(high_violations)
            })
        
        # Priority 3: Medium violations
        medium_violations = [v for v in violations if v.get('severity') == 'MEDIUM']
        if medium_violations:
            recommendations.append({
                'priority': 'P3_MEDIUM',
                'action': 'Include in next maintenance cycle',
                'description': 'Address during planned maintenance windows',
                'timeline': 'Within 1-3 months',
                'violations_addressed': len(medium_violations)
            })
        
        return recommendations
    
    def _assess_business_impact(self, ci_data: Dict, analysis: Dict) -> str:
        """Assess business impact of compliance violations"""
        
        # This would typically consider business service dependencies,
        # criticality ratings, etc. from CMDB
        
        risk_score = analysis.get('risk_score', 0)
        critical_violations = len([v for v in analysis.get('violations', []) if v.get('severity') == 'CRITICAL'])
        
        if critical_violations > 0 and risk_score >= 80:
            return 'CRITICAL_BUSINESS_IMPACT'
        elif risk_score >= 60:
            return 'HIGH_BUSINESS_IMPACT'
        elif risk_score >= 30:
            return 'MEDIUM_BUSINESS_IMPACT'
        else:
            return 'LOW_BUSINESS_IMPACT'
    
    def analyze_ci_list(self, ci_list: List[Dict]) -> Dict:
        """Analyze compliance for multiple CIs"""
        
        print(f"🔍 Analyzing compliance for {len(ci_list)} CIs...")
        
        results = []
        summary_stats = {
            'total_systems': len(ci_list),
            'compliant': 0,
            'at_risk': 0,
            'non_compliant': 0,
            'monitoring_required': 0,
            'critical_violations': 0,
            'high_violations': 0,
            'eol_systems': 0,
            'eos_systems': 0
        }
        
        for ci in ci_list:
            analysis = self.analyze_ci_compliance(ci)
            results.append(analysis)
            
            # Update summary statistics
            status = analysis.get('compliance_status', 'UNKNOWN')
            if status == 'COMPLIANT':
                summary_stats['compliant'] += 1
            elif status == 'AT_RISK':
                summary_stats['at_risk'] += 1
            elif status == 'NON_COMPLIANT':
                summary_stats['non_compliant'] += 1
            elif status == 'MONITORING_REQUIRED':
                summary_stats['monitoring_required'] += 1
            
            # Count violations
            for violation in analysis.get('violations', []):
                severity = violation.get('severity', 'LOW')
                violation_type = violation.get('type', '')
                
                if severity == 'CRITICAL':
                    summary_stats['critical_violations'] += 1
                elif severity == 'HIGH':
                    summary_stats['high_violations'] += 1
                
                if 'eol' in violation_type:
                    summary_stats['eol_systems'] += 1
                elif 'eos' in violation_type:
                    summary_stats['eos_systems'] += 1
        
        compliance_report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyzer_version': '1.0',
                'total_systems_analyzed': len(ci_list)
            },
            'summary_statistics': summary_stats,
            'detailed_results': results,
            'compliance_score': self._calculate_overall_compliance_score(summary_stats)
        }
        
        print(f"✅ Compliance analysis completed")
        print(f"   📊 {summary_stats['compliant']} compliant, {summary_stats['non_compliant']} non-compliant")
        print(f"   ⚠️  {summary_stats['critical_violations']} critical violations found")
        
        return compliance_report
    
    def _calculate_overall_compliance_score(self, stats: Dict) -> int:
        """Calculate organization-wide compliance score"""
        
        total = stats['total_systems']
        if total == 0:
            return 0
        
        compliant_weight = stats['compliant'] * 100
        monitoring_weight = stats['monitoring_required'] * 80
        at_risk_weight = stats['at_risk'] * 60
        non_compliant_weight = stats['non_compliant'] * 20
        
        total_weighted = compliant_weight + monitoring_weight + at_risk_weight + non_compliant_weight
        compliance_score = int(total_weighted / total)
        
        return compliance_score
    
    def export_compliance_report(self, compliance_data: Dict, filename: str = None) -> str:
        """Export compliance analysis to JSON and CSV"""
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"compliance_report_{timestamp}"
        
        # Export JSON
        json_file = f"{filename}.json"
        with open(json_file, 'w') as f:
            json.dump(compliance_data, f, indent=2, default=str)
        
        # Export CSV summary
        csv_file = f"{filename}_summary.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'CI_Name', 'IP_Address', 'OS_Name', 'OS_Version', 
                'Compliance_Status', 'Risk_Score', 'Critical_Violations',
                'EOL_Status', 'Business_Impact'
            ])
            
            # Data rows
            for result in compliance_data.get('detailed_results', []):
                critical_count = len([v for v in result.get('violations', []) if v.get('severity') == 'CRITICAL'])
                eol_status = 'EOL' if any('eol' in v.get('type', '') for v in result.get('violations', [])) else 'OK'
                
                writer.writerow([
                    result.get('ci_name', ''),
                    result.get('ip_address', ''),
                    result.get('os_name', ''),
                    result.get('os_version', ''),
                    result.get('compliance_status', ''),
                    result.get('risk_score', 0),
                    critical_count,
                    eol_status,
                    result.get('business_impact', '')
                ])
        
        print(f"📄 Compliance report exported:")
        print(f"   JSON: {json_file}")
        print(f"   CSV:  {csv_file}")
        
        return json_file

# Demo function
def demo_compliance_analysis():
    """Demonstrate compliance analysis"""
    
    print("🔍 Compliance Analysis Demo")
    print("=" * 40)
    
    # Sample CI data for testing
    test_cis = [
        {
            'ci_name': 'legacy-server-01',
            'ip_address': '10.1.1.10',
            'detected_os': 'Windows Server 2008 R2',
            'detected_version': '2008 R2',
            'cmdb_os': 'Windows Server 2008 R2',
            'cmdb_version': '2008 R2'
        },
        {
            'ci_name': 'web-server-02',
            'ip_address': '10.1.1.20', 
            'detected_os': 'Ubuntu',
            'detected_version': '16.04',
            'cmdb_os': 'Ubuntu 16.04',
            'cmdb_version': '16.04'
        },
        {
            'ci_name': 'app-server-03',
            'ip_address': '10.1.1.30',
            'detected_os': 'Windows Server 2019',
            'detected_version': '2019',
            'cmdb_os': 'Windows Server 2019',
            'cmdb_version': '2019'
        }
    ]
    
    analyzer = ComplianceAnalyzer()
    compliance_report = analyzer.analyze_ci_list(test_cis)
    
    # Export report
    analyzer.export_compliance_report(compliance_report)
    
    # Show summary
    stats = compliance_report['summary_statistics']
    print(f"\n📊 Compliance Summary:")
    print(f"   Compliance Score: {compliance_report['compliance_score']}%")
    print(f"   Non-Compliant Systems: {stats['non_compliant']}")
    print(f"   Critical Violations: {stats['critical_violations']}")
    print(f"   EOL Systems: {stats['eol_systems']}")

if __name__ == "__main__":
    demo_compliance_analysis()