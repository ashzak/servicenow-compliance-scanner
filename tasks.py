#!/usr/bin/env python3
"""
ServiceNow CMDB Compliance Scanner - CrewAI Tasks
"""

from crewai import Task

def create_scanning_tasks(target_scope="all"):
    """Create task sequence for CMDB compliance scanning"""
    
    # Task 1: ServiceNow CMDB Data Extraction
    servicenow_extraction_task = Task(
        description=f"""Extract Configuration Items (CIs) from ServiceNow CMDB for compliance scanning.

        Your mission:
        1. Connect to ServiceNow CMDB using provided credentials
        2. Query for network elements and servers in scope: {target_scope}  
        3. Extract CI data including:
           - CI Name, IP Address, FQDN
           - Current OS Name and Version (as recorded in CMDB)
           - CI Class (Server, Router, Switch, Firewall, etc.)
           - Business Service Dependencies
           - Last Discovery Date
           - Assigned To / Managed By
        4. Identify CIs with missing or outdated OS information
        5. Create structured dataset for further analysis
        
        Focus on network infrastructure and server CIs that:
        - Have IP addresses assigned
        - Are in 'Operational' or 'Production' state
        - Have OS information recorded
        - Are critical to business operations
        
        Output: Structured JSON dataset with all discovered CIs and their attributes""",
        expected_output="JSON dataset containing discovered CIs with OS information, IP addresses, and metadata",
        agent_name="servicenow_agent"
    )
    
    # Task 2: Network Scanning & OS Detection
    network_scanning_task = Task(
        description="""Scan network elements to detect actual OS versions and validate CMDB accuracy.

        Your mission:
        1. Take the CI dataset from ServiceNow extraction
        2. For each CI with an IP address, perform OS detection:
           - Use Nmap for OS fingerprinting
           - Attempt SSH connections for banner grabbing
           - Try SNMP queries for system information
           - Use HTTP/HTTPS for web-based devices
        3. Compare detected OS with CMDB records
        4. Identify discrepancies and data quality issues
        5. Gather additional system information:
           - Actual OS version and build numbers
           - Patch levels and updates installed
           - System uptime and last reboot
           - Running services and open ports
        6. Flag unreachable or inaccessible systems
        
        Security considerations:
        - Use non-intrusive scanning methods
        - Respect rate limits and network policies
        - Document access failures and permission issues
        
        Output: Enhanced dataset with actual OS information and CMDB validation results""",
        expected_output="Enhanced CI dataset with real OS versions, scan results, and CMDB accuracy assessment",
        agent_name="network_scanner_agent"
    )
    
    # Task 3: Compliance Analysis & Risk Assessment
    compliance_analysis_task = Task(
        description="""Analyze OS versions for compliance violations, end-of-life status, and security risks.

        Your mission:
        1. Take the validated CI dataset with actual OS information
        2. For each system, perform comprehensive compliance analysis:
           - Check OS End-of-Life (EOL) status against vendor lifecycle data
           - Identify End-of-Support (EOS) dates
           - Assess security vulnerability exposure
           - Check against enterprise security policies
           - Evaluate regulatory compliance requirements
        3. Categorize compliance violations by severity:
           - CRITICAL: EOL systems with active security threats
           - HIGH: EOS systems approaching EOL
           - MEDIUM: Systems missing security patches
           - LOW: Systems with minor version updates available
        4. Research upgrade paths and compatibility:
           - Available OS upgrade options
           - Hardware compatibility requirements
           - Business impact of upgrades
        5. Calculate risk scores based on:
           - Business criticality
           - Security exposure
           - Compliance requirements
           - Operational impact
           
        Reference current vendor EOL databases:
        - Microsoft Windows lifecycle
        - Linux distribution support cycles
        - Network device OS support (Cisco, Juniper, etc.)
        - Unix/AIX support timelines
        
        Output: Comprehensive compliance assessment with risk scores and remediation priorities""",
        expected_output="Detailed compliance analysis with risk classifications, EOL status, and security assessments",
        agent_name="compliance_agent"
    )
    
    # Task 4: Executive Reporting & Remediation Planning
    reporting_task = Task(
        description="""Generate executive compliance reports and actionable remediation plans.

        Your mission:
        1. Synthesize all previous analysis into comprehensive reports
        2. Create executive summary with:
           - Overall compliance posture
           - Critical risk exposure
           - Business impact assessment
           - Budget and resource requirements
        3. Generate detailed technical reports including:
           - System-by-system compliance status
           - Prioritized remediation roadmap
           - Cost estimates for upgrades
           - Implementation timelines
        4. Develop remediation strategies:
           - Emergency patches for critical systems
           - Planned upgrade schedules
           - End-of-life replacement planning
           - Risk mitigation alternatives
        5. Create actionable work orders:
           - Immediate actions required
           - Maintenance window planning
           - Resource allocation needs
           - Success metrics and KPIs
        
        Report formats needed:
        - Executive dashboard (high-level metrics)
        - Technical compliance report (detailed findings)
        - Remediation project plan (timeline and resources)
        - Risk register (ongoing monitoring)
        
        Focus on business value:
        - Quantify security risk reduction
        - Calculate compliance cost avoidance
        - Demonstrate operational improvements
        - Show ROI of remediation investments
        
        Output: Multi-format compliance reports with executive summaries and detailed remediation plans""",
        expected_output="Complete compliance report package with executive summaries, technical details, and remediation roadmaps",
        agent_name="reporting_agent"
    )
    
    return [
        servicenow_extraction_task,
        network_scanning_task, 
        compliance_analysis_task,
        reporting_task
    ]