#!/usr/bin/env python3
"""
ServiceNow CMDB Compliance Scanner - CrewAI Orchestration
"""

from crewai import Crew, Process
from agents import (
    servicenow_agent,
    network_scanner_agent, 
    compliance_agent,
    reporting_agent
)
from tasks import create_scanning_tasks
import json
import os
from datetime import datetime

class ComplianceScanningCrew:
    """Main crew orchestrator for CMDB compliance scanning"""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"compliance_scan_{self.scan_id}"
        os.makedirs(self.output_dir, exist_ok=True)
        
    def run_compliance_scan(self, target_scope: str = "all") -> dict:
        """Execute complete compliance scanning workflow"""
        
        print(f"🔍 Starting ServiceNow CMDB Compliance Scan")
        print(f"📊 Scan ID: {self.scan_id}")
        print(f"🎯 Target Scope: {target_scope}")
        print(f"📁 Output Directory: {self.output_dir}")
        print()
        
        # Create tasks for this scan
        tasks = create_scanning_tasks(target_scope)
        
        # Map agent names to actual agent objects
        agent_mapping = {
            "servicenow_agent": servicenow_agent,
            "network_scanner_agent": network_scanner_agent,
            "compliance_agent": compliance_agent,
            "reporting_agent": reporting_agent
        }
        
        # Assign agents to tasks
        for task in tasks:
            if hasattr(task, 'agent_name'):
                task.agent = agent_mapping[task.agent_name]
        
        # Create and configure crew
        crew = Crew(
            agents=[
                servicenow_agent,
                network_scanner_agent,
                compliance_agent, 
                reporting_agent
            ],
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=True,
            embedder={
                "provider": "openai",
                "config": {
                    "model": "text-embedding-3-small"
                }
            }
        )
        
        try:
            print("🚀 Executing compliance scanning crew...")
            print("=" * 60)
            
            # Execute the crew
            result = crew.kickoff()
            
            print("=" * 60)
            print("✅ Compliance scan completed successfully!")
            
            # Process and save results
            scan_results = self._process_results(result)
            
            return {
                "success": True,
                "scan_id": self.scan_id,
                "results": scan_results,
                "output_directory": self.output_dir,
                "summary": self._generate_summary(scan_results)
            }
            
        except Exception as e:
            print(f"❌ Compliance scan failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "scan_id": self.scan_id
            }
    
    def _process_results(self, crew_result) -> dict:
        """Process and structure crew execution results"""
        
        # Extract results from crew execution
        if hasattr(crew_result, 'tasks_output'):
            task_outputs = crew_result.tasks_output
        else:
            task_outputs = [crew_result] if crew_result else []
        
        processed_results = {
            "servicenow_data": {},
            "scanning_results": {},
            "compliance_analysis": {},
            "reports": {},
            "execution_metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "scan_id": self.scan_id,
                "tasks_completed": len(task_outputs)
            }
        }
        
        # Process each task output
        for i, output in enumerate(task_outputs):
            task_name = f"task_{i+1}"
            
            if hasattr(output, 'raw'):
                content = output.raw
            else:
                content = str(output)
            
            # Save individual task output
            output_file = os.path.join(self.output_dir, f"{task_name}_output.txt")
            with open(output_file, 'w') as f:
                f.write(content)
            
            # Categorize by task type
            if i == 0:  # ServiceNow extraction
                processed_results["servicenow_data"] = {
                    "raw_output": content,
                    "output_file": output_file
                }
            elif i == 1:  # Network scanning
                processed_results["scanning_results"] = {
                    "raw_output": content,
                    "output_file": output_file
                }
            elif i == 2:  # Compliance analysis  
                processed_results["compliance_analysis"] = {
                    "raw_output": content,
                    "output_file": output_file
                }
            elif i == 3:  # Reporting
                processed_results["reports"] = {
                    "raw_output": content,
                    "output_file": output_file
                }
        
        # Save complete results
        results_file = os.path.join(self.output_dir, "complete_results.json")
        with open(results_file, 'w') as f:
            json.dump(processed_results, f, indent=2, default=str)
        
        return processed_results
    
    def _generate_summary(self, results: dict) -> dict:
        """Generate high-level summary of scan results"""
        
        summary = {
            "scan_overview": {
                "scan_id": self.scan_id,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "completed",
                "output_directory": self.output_dir
            },
            "task_completion": {
                "servicenow_extraction": bool(results.get("servicenow_data")),
                "network_scanning": bool(results.get("scanning_results")),
                "compliance_analysis": bool(results.get("compliance_analysis")),
                "report_generation": bool(results.get("reports"))
            },
            "next_steps": [
                "Review generated compliance reports",
                "Validate scanning results",
                "Plan remediation activities",
                "Schedule follow-up scans"
            ]
        }
        
        # Save summary
        summary_file = os.path.join(self.output_dir, "scan_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary

# Convenience function for standalone execution
def run_compliance_scan(target_scope: str = "all", config: dict = None) -> dict:
    """Run compliance scan with default configuration"""
    crew = ComplianceScanningCrew(config)
    return crew.run_compliance_scan(target_scope)